package btcman

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// BtcRpcClienter is the interface for comunicating with the BTC node
type BtcRpcClienter interface {
	CreateRawTransaction([]btcjson.TransactionInput, map[btcutil.Address]btcutil.Amount, *int64) (*wire.MsgTx, error)
	SignRawTransactionWithWallet(*wire.MsgTx) (*wire.MsgTx, bool, error)
	SendRawTransaction(*wire.MsgTx, bool) (*chainhash.Hash, error)
	GetRawTransactionVerbose(*chainhash.Hash) (*btcjson.TxRawResult, error)
	GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error)
	Shutdown()
}

// Clienter is the interface for creating inscriptions in a btc transaction
type Clienter interface {
	Inscribe(data []byte) (string, error)
	DecodeInscription() (string, error)
	Shutdown()
}
