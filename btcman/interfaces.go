package btcman

import (
	"github.com/0xPolygon/cdk/btcman/indexer"
	"github.com/btcsuite/btcd/wire"
)

// Clienter is the interface for creating inscriptions in a btc transaction
type Clienter interface {
	Inscribe(data []byte) error
	DecodeInscription() (string, error)
	Shutdown()
}

type Keychainer interface {
	SignTransaction(rawTransaction *wire.MsgTx, indexer indexer.Indexerer) error
	GetPublicKey() string
}
