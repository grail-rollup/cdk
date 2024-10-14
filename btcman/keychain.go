package btcman

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/0xPolygon/cdk/btcman/indexer"
	"github.com/0xPolygon/cdk/log"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// keychain represents an agglomeration of the keys used inside the btcman and btc indexer
type keychain struct {
	privateKeyWIF string
	privateKey    *secp256k1.PrivateKey
	publicKey     *secp256k1.PublicKey
	network       *chaincfg.Params
	indexer       indexer.Indexerer
	logger        *log.Logger
}

func NewKeychain(privateKeyWIF string, indexer indexer.Indexerer, network *chaincfg.Params, logger *log.Logger) (Keychainer, error) {
	wif, err := btcutil.DecodeWIF(privateKeyWIF)
	if err != nil {
		return nil, fmt.Errorf("error decoding wif private key")
	}
	privateKey := wif.PrivKey
	publicKey := privateKey.PubKey()

	return &keychain{
		logger:        logger,
		privateKeyWIF: privateKeyWIF,
		publicKey:     publicKey,
		privateKey:    privateKey,
		indexer:       indexer,
		network:       network,
	}, nil
}

// SignTransaction signs a provided unsigned transaction, indexer is used for retrieving the necessary information about previous transactions
func (k *keychain) SignTransaction(rawTransaction *wire.MsgTx, indexer indexer.Indexerer) error {
	for idx, txInput := range rawTransaction.TxIn {

		prevTx, err := indexer.GetTransaction(context.Background(), txInput.PreviousOutPoint.Hash.String(), true)
		if err != nil {
			return err
		}

		subscript, err := hex.DecodeString(prevTx.Vout[txInput.PreviousOutPoint.Index].ScriptPubKey.Hex)
		if err != nil {
			return err
		}

		amount := int64(prevTx.Vout[txInput.PreviousOutPoint.Index].Value * btcutil.SatoshiPerBitcoin)

		signature, err := k.generateSignature(rawTransaction, idx, amount, subscript)
		if err != nil {
			return err
		}

		txInput.Witness = signature
	}
	k.logger.Info("Transaction signed successfully")
	return nil
}

// generateSignature is a helper for SignTransaction that generates the actual signatures
func (k *keychain) generateSignature(tx *wire.MsgTx, idx int, amt int64, subscript []byte) (wire.TxWitness, error) {
	prevOutFetcher := NewPreviousOutPointFetcher(k.indexer, k.logger)

	wifKey, err := btcutil.DecodeWIF(k.privateKeyWIF)
	if err != nil {
		return nil, fmt.Errorf("failed to decode WIF: %v", err)
	}

	privKey := wifKey.PrivKey
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	signature, err := txscript.WitnessSignature(
		tx,
		sigHashes,
		idx,
		amt,
		subscript,
		txscript.SigHashAll,
		privKey,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return signature, nil
}

// GetPublicKey returns the public key as string
func (k *keychain) GetPublicKey() string {
	return hex.EncodeToString(k.publicKey.SerializeCompressed())
}
