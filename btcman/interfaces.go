package btcman

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// BtcRpcClienter is the interface for comunicating with the BTC node
type BtcRpcClienter interface {
	ListUnspentMinMaxAddresses(int, int, []btcutil.Address) ([]btcjson.ListUnspentResult, error)
	CreateRawTransaction([]btcjson.TransactionInput, map[btcutil.Address]btcutil.Amount, *int64) (*wire.MsgTx, error)
	SignRawTransactionWithWallet(*wire.MsgTx) (*wire.MsgTx, bool, error)
	SendRawTransaction(*wire.MsgTx, bool) (*chainhash.Hash, error)
	GetTransaction(*chainhash.Hash) (*btcjson.GetTransactionResult, error)
	GetRawTransactionVerbose(*chainhash.Hash) (*btcjson.TxRawResult, error)
	Shutdown()
}

// BtcInscriptorer is the interface for creating inscriptions in a btc transaction
type BtcInscriptorer interface {
	Shutdown()
	Inscribe(message string) (string, error)
	DecodeInscription(txHash, separator string) error
}
