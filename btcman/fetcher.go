package btcman

import (
	"context"
	"encoding/hex"

	"github.com/0xPolygon/cdk/btcman/indexer"
	"github.com/0xPolygon/cdk/log"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// PreviousOutPointFetcher implements txscript.PrevOutputFetcher interface
// and is used during the signing to retrieve the previous transaction
type PreviousOutPointFetcher struct {
	indexer indexer.Indexerer
	logger  *log.Logger
}

func NewPreviousOutPointFetcher(indexer indexer.Indexerer, logger *log.Logger) txscript.PrevOutputFetcher {
	return &PreviousOutPointFetcher{
		indexer: indexer,
		logger:  logger,
	}
}

// FetchPrevOutput retursn a transaction out by a given outPoint
func (f *PreviousOutPointFetcher) FetchPrevOutput(outPoint wire.OutPoint) *wire.TxOut {
	tx, err := f.indexer.GetTransaction(context.Background(), outPoint.Hash.String(), true)
	if err != nil {
		f.logger.Fatal(err)
	}
	vout := tx.Vout[outPoint.Index]
	scriptPub, err := hex.DecodeString(vout.ScriptPubKey.Hex)
	if err != nil {
		f.logger.Fatal(err)
	}
	txOut := wire.NewTxOut(int64(vout.Value), scriptPub)
	return txOut
}
