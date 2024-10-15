package indexer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/crypto/ripemd160"
)

// PrivateKeyToPublicKey returns a public key string by a given private key
func PrivateKeyToPublicKey(privateKey string) (string, error) {
	wif, err := btcutil.DecodeWIF(privateKey)
	if err != nil {
		return "", err
	}
	pk := wif.PrivKey
	publicKey := pk.PubKey()
	return hex.EncodeToString(publicKey.SerializeCompressed()), nil
}

// PrivateKeyToAddress returns an address by a given private key
func PrivateKeyToAddress(privateKeyStr string, network *chaincfg.Params) (btcutil.Address, error) {
	privateKey, err := btcutil.DecodeWIF(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	publicKey := privateKey.PrivKey.PubKey()

	publicKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	address, err := btcutil.NewAddressWitnessPubKeyHash(publicKeyHash, network)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P2WPKH address: %v", err)
	}

	return address, nil
}

// privateKeyToAddress returns a script hash by a given public key
func publicKeyToScriptHash(publicKey string) (string, error) {
	sha256Hashed, err := calculateSHA256(publicKey)
	if err != nil {
		return "", fmt.Errorf("error hashing public key with sha256: %s", err)
	}
	pkHash := calculateRIPEMD160(sha256Hashed)

	pubScript := fmt.Sprintf("0014%s", hex.EncodeToString(pkHash))

	scriptHash, err := calculateSHA256(pubScript)
	if err != nil {
		return "", fmt.Errorf("error hashing public key with sha256: %s", err)
	}

	bigEndianBytes := make([]byte, len(scriptHash))
	err = convertEndianess(scriptHash, bigEndianBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bigEndianBytes), nil
}

// calculateSHA256 returns a hash of data, using sha256 hashing function
func calculateSHA256(data string) ([]byte, error) {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key string: %s", err)
	}
	hash := sha256.New()
	hash.Write(dataBytes)
	sum := hash.Sum(nil)

	return sum, nil
}

// calculateRIPEMD160 returns a hash of data, using ripemd160 hashing function
func calculateRIPEMD160(data []byte) []byte {
	hash := ripemd160.New()
	hash.Write(data)
	sum := hash.Sum(nil)

	return sum
}

// convertEndianess changes the endianes of the provided data
func convertEndianess(src []byte, dst []byte) error {
	if len(src) != len(dst) {
		return fmt.Errorf("source and destination slices must be of the same length")
	}
	for i := range src {
		dst[len(src)-1-i] = src[i]
	}
	return nil
}

// GetTxHex serializes a transaction and returns it as hex
func GetTxHex(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}
