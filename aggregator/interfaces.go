package aggregator

import (
	"context"
	"math/big"

	ethmanTypes "github.com/0xPolygon/cdk/aggregator/ethmantypes"
	"github.com/0xPolygon/cdk/aggregator/prover"
	"github.com/0xPolygon/cdk/state"
	"github.com/0xPolygonHermez/zkevm-data-streamer/datastreamer"
	"github.com/0xPolygonHermez/zkevm-ethtx-manager/ethtxmanager"
	"github.com/0xPolygonHermez/zkevm-synchronizer-l1/synchronizer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/jackc/pgx/v4"
)

// Consumer interfaces required by the package.

type ProverInterface interface {
	Name() string
	ID() string
	Addr() string
	IsIdle() (bool, error)
	BatchProof(input *prover.StatelessInputProver) (*string, error)
	AggregatedProof(inputProof1, inputProof2 string) (*string, error)
	FinalProof(inputProof string, aggregatorAddr string) (*string, error)
	WaitRecursiveProof(ctx context.Context, proofID string) (string, common.Hash, error)
	WaitFinalProof(ctx context.Context, proofID string) (*prover.FinalProof, error)
}

// Etherman contains the methods required to interact with ethereum
type Etherman interface {
	GetRollupId() uint32
	GetLatestVerifiedBatchNum() (uint64, error)
	BuildTrustedVerifyBatchesTxData(
		lastVerifiedBatch, newVerifiedBatch uint64, inputs *ethmanTypes.FinalProofInputs, beneficiary common.Address,
	) (to *common.Address, data []byte, err error)
	GetLatestBlockHeader(ctx context.Context) (*types.Header, error)
	GetBatchAccInputHash(ctx context.Context, batchNumber uint64) (common.Hash, error)
}

// aggregatorTxProfitabilityChecker interface for different profitability
// checking algorithms.
type aggregatorTxProfitabilityChecker interface {
	IsProfitable(context.Context, *big.Int) (bool, error)
}

// StateInterface gathers the methods to interact with the state.
type StateInterface interface {
	BeginStateTransaction(ctx context.Context) (pgx.Tx, error)
	CheckProofContainsCompleteSequences(ctx context.Context, proof *state.Proof, dbTx pgx.Tx) (bool, error)
	GetProofReadyToVerify(ctx context.Context, lastVerfiedBatchNumber uint64, dbTx pgx.Tx) (*state.Proof, error)
	GetProofsToAggregate(ctx context.Context, dbTx pgx.Tx) (*state.Proof, *state.Proof, error)
	AddGeneratedProof(ctx context.Context, proof *state.Proof, dbTx pgx.Tx) error
	UpdateGeneratedProof(ctx context.Context, proof *state.Proof, dbTx pgx.Tx) error
	DeleteGeneratedProofs(ctx context.Context, batchNumber uint64, batchNumberFinal uint64, dbTx pgx.Tx) error
	DeleteUngeneratedProofs(ctx context.Context, dbTx pgx.Tx) error
	CleanupGeneratedProofs(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) error
	CleanupLockedProofs(ctx context.Context, duration string, dbTx pgx.Tx) (int64, error)
	CheckProofExistsForBatch(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) (bool, error)
	AddSequence(ctx context.Context, sequence state.Sequence, dbTx pgx.Tx) error
	AddBatch(ctx context.Context, dbBatch *state.DBBatch, dbTx pgx.Tx) error
	GetBatch(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) (*state.DBBatch, error)
	DeleteBatchesOlderThanBatchNumber(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) error
	DeleteBatchesNewerThanBatchNumber(ctx context.Context, batchNumber uint64, dbTx pgx.Tx) error
}

// SynchronizerInterface defines all the methods that are part of the Synchronizer interface
type SynchronizerInterface interface {
	// Methods from SynchronizerBlockQuerier
	GetL1BlockByNumber(ctx context.Context, blockNumber uint64) (*synchronizer.L1Block, error)
	GetLastL1Block(ctx context.Context) (*synchronizer.L1Block, error)

	// Methods from SynchronizerL1InfoTreeQuerier
	GetL1InfoRootPerIndex(ctx context.Context, L1InfoTreeIndex uint32) (common.Hash, error)
	GetL1InfoTreeLeaves(ctx context.Context, indexLeaves []uint32) (map[uint32]synchronizer.L1InfoTreeLeaf, error)
	GetLeafsByL1InfoRoot(ctx context.Context, l1InfoRoot common.Hash) ([]synchronizer.L1InfoTreeLeaf, error)

	// Methods from SynchronizerVirtualBatchesQuerier
	GetLastestVirtualBatchNumber(ctx context.Context) (uint64, error)
	GetVirtualBatchByBatchNumber(ctx context.Context, batchNumber uint64) (*synchronizer.VirtualBatch, error)

	// Methods from SynchronizerSequencedBatchesQuerier
	GetSequenceByBatchNumber(ctx context.Context, batchNumber uint64) (*synchronizer.SequencedBatches, error)

	// Methods from SynchornizerStatusQuerier
	IsSynced() bool

	// Methods from SynchronizerReorgSupporter
	SetCallbackOnReorgDone(callback func(reorgData synchronizer.ReorgExecutionResult))

	// Methods from SynchronizerRollbackBatchesSupporter
	SetCallbackOnRollbackBatches(callback func(data synchronizer.RollbackBatchesData))

	// Methods from SynchronizerRunner
	Stop()
	Sync(returnOnSync bool) error
}

// StreamClient represents the stream client behaviour
type StreamClient interface {
	Start() error
	ExecCommandStart(fromEntry uint64) error
	ExecCommandStartBookmark(fromBookmark []byte) error
	ExecCommandStop() error
	ExecCommandGetHeader() (datastreamer.HeaderEntry, error)
	ExecCommandGetEntry(fromEntry uint64) (datastreamer.FileEntry, error)
	ExecCommandGetBookmark(fromBookmark []byte) (datastreamer.FileEntry, error)
	GetFromStream() uint64
	GetTotalEntries() uint64
	SetProcessEntryFunc(f datastreamer.ProcessEntryFunc)
	ResetProcessEntryFunc()
	IsStarted() bool
}

// EthTxManagerClient represents the eth tx manager interface
type EthTxManagerClient interface {
	Add(ctx context.Context, to *common.Address, value *big.Int, data []byte, gasOffset uint64, sidecar *types.BlobTxSidecar) (common.Hash, error)
	AddWithGas(ctx context.Context, to *common.Address, value *big.Int, data []byte, gasOffset uint64, sidecar *types.BlobTxSidecar, gas uint64) (common.Hash, error)
	EncodeBlobData(data []byte) (kzg4844.Blob, error)
	MakeBlobSidecar(blobs []kzg4844.Blob) *types.BlobTxSidecar
	ProcessPendingMonitoredTxs(ctx context.Context, resultHandler ethtxmanager.ResultHandler)
	Remove(ctx context.Context, id common.Hash) error
	RemoveAll(ctx context.Context) error
	Result(ctx context.Context, id common.Hash) (ethtxmanager.MonitoredTxResult, error)
	ResultsByStatus(ctx context.Context, statuses []ethtxmanager.MonitoredTxStatus) ([]ethtxmanager.MonitoredTxResult, error)
	Start()
	Stop()
}
