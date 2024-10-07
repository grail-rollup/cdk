package btcman

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
)

func privateToPublicKey(privateKeyString string) (string, error) {
	wif, err := btcutil.DecodeWIF(privateKeyString)
	if err != nil {
		return "", err
	}
	privateKey := wif.PrivKey
	publicKey := privateKey.PubKey()
	return hex.EncodeToString(publicKey.SerializeCompressed()), nil
}
