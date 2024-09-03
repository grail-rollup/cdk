package bridgesync

import (
	"context"
	"time"

	"github.com/0xPolygon/cdk/etherman"
	"github.com/0xPolygon/cdk/sync"
	"github.com/0xPolygon/cdk/tree"
	"github.com/ethereum/go-ethereum/common"
)

const (
	bridgeSyncL1       = "bridgesyncl1"
	bridgeSyncL2       = "bridgesyncl2"
	downloadBufferSize = 1000
)

type BridgeSync struct {
	processor *processor
	driver    *sync.EVMDriver
}

// NewL1 creates a bridge syncer that synchronizes the mainnet exit tree
func NewL1(
	ctx context.Context,
	dbPath string,
	bridge common.Address,
	syncBlockChunkSize uint64,
	blockFinalityType etherman.BlockNumberFinality,
	rd sync.ReorgDetector,
	ethClient EthClienter,
	initialBlock uint64,
	waitForNewBlocksPeriod time.Duration,
	retryAfterErrorPeriod time.Duration,
	maxRetryAttemptsAfterError int,
) (*BridgeSync, error) {
	return newBridgeSync(
		ctx,
		dbPath,
		bridge,
		syncBlockChunkSize,
		blockFinalityType,
		rd,
		ethClient,
		initialBlock,
		bridgeSyncL1,
		waitForNewBlocksPeriod,
		retryAfterErrorPeriod,
		maxRetryAttemptsAfterError,
		false,
	)
}

// NewL2 creates a bridge syncer that synchronizes the local exit tree
func NewL2(
	ctx context.Context,
	dbPath string,
	bridge common.Address,
	syncBlockChunkSize uint64,
	blockFinalityType etherman.BlockNumberFinality,
	rd sync.ReorgDetector,
	ethClient EthClienter,
	initialBlock uint64,
	waitForNewBlocksPeriod time.Duration,
	retryAfterErrorPeriod time.Duration,
	maxRetryAttemptsAfterError int,
) (*BridgeSync, error) {
	return newBridgeSync(
		ctx,
		dbPath,
		bridge,
		syncBlockChunkSize,
		blockFinalityType,
		rd,
		ethClient,
		initialBlock,
		bridgeSyncL2,
		waitForNewBlocksPeriod,
		retryAfterErrorPeriod,
		maxRetryAttemptsAfterError,
		true,
	)
}

func newBridgeSync(
	ctx context.Context,
	dbPath string,
	bridge common.Address,
	syncBlockChunkSize uint64,
	blockFinalityType etherman.BlockNumberFinality,
	rd sync.ReorgDetector,
	ethClient EthClienter,
	initialBlock uint64,
	l1OrL2ID string,
	waitForNewBlocksPeriod time.Duration,
	retryAfterErrorPeriod time.Duration,
	maxRetryAttemptsAfterError int,
	syncFullClaims bool,
) (*BridgeSync, error) {
	processor, err := newProcessor(dbPath, l1OrL2ID)
	if err != nil {
		return nil, err
	}
	lastProcessedBlock, err := processor.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, err
	}
	if lastProcessedBlock < initialBlock {
		err = processor.ProcessBlock(ctx, sync.Block{
			Num: initialBlock,
		})
		if err != nil {
			return nil, err
		}
	}
	rh := &sync.RetryHandler{
		MaxRetryAttemptsAfterError: maxRetryAttemptsAfterError,
		RetryAfterErrorPeriod:      retryAfterErrorPeriod,
	}

	appender, err := buildAppender(ethClient, bridge, syncFullClaims)
	if err != nil {
		return nil, err
	}
	downloader, err := sync.NewEVMDownloader(
		l1OrL2ID,
		ethClient,
		syncBlockChunkSize,
		blockFinalityType,
		waitForNewBlocksPeriod,
		appender,
		[]common.Address{bridge},
		rh,
	)
	if err != nil {
		return nil, err
	}

	driver, err := sync.NewEVMDriver(rd, processor, downloader, l1OrL2ID, downloadBufferSize, rh)
	if err != nil {
		return nil, err
	}
	return &BridgeSync{
		processor: processor,
		driver:    driver,
	}, nil
}

// Start starts the synchronization process
func (s *BridgeSync) Start(ctx context.Context) {
	s.driver.Sync(ctx)
}

func (s *BridgeSync) GetLastProcessedBlock(ctx context.Context) (uint64, error) {
	return s.processor.GetLastProcessedBlock(ctx)
}

func (s *BridgeSync) GetBridgeRootByHash(ctx context.Context, root common.Hash) (tree.Root, error) {
	return s.processor.exitTree.GetRootByHash(ctx, root)
}

func (s *BridgeSync) GetClaims(ctx context.Context, fromBlock, toBlock uint64) ([]Claim, error) {
	return s.processor.GetClaims(ctx, fromBlock, toBlock)
}

func (s *BridgeSync) GetBridges(ctx context.Context, fromBlock, toBlock uint64) ([]Bridge, error) {
	return s.processor.GetBridges(ctx, fromBlock, toBlock)
}

func (s *BridgeSync) GetProof(ctx context.Context, depositCount uint32, localExitRoot common.Hash) ([32]common.Hash, error) {
	return s.processor.exitTree.GetProof(ctx, depositCount, localExitRoot)
}
