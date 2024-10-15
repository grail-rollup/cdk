package indexer

import (
	"context"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
)

type Indexerer interface {
	Start(string)
	ListUnspent(context.Context, string) ([]*UTXO, error)
	GetTransaction(context.Context, string, bool) (*btcjson.TxRawResult, error)
	GetBlockchainInfo(ctx context.Context) (*BlockChainInfo, error)
	SendTransaction(ctx context.Context, transactionHex *wire.MsgTx) (string, error)
	GetLastInscribedTransactionByPublicKey(ctx context.Context, publicKey string, blblockchainHeight int32, utxoThreshold float64) (*TxInfo, error)
	Disconnect()
}
