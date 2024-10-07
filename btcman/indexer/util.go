package indexer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

// publicKeyToScriptHash calculates a scripts hash from a given public key
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
		return "", fmt.Errorf("error changing endianess: %s", err)
	}
	return hex.EncodeToString(bigEndianBytes), nil
}

// calculateSHA256 returns the hash of data using sha256
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

// calculateRIPEMD160 returns the hash of data using ripemd160
func calculateRIPEMD160(data []byte) []byte {
	hash := ripemd160.New()
	hash.Write(data)
	sum := hash.Sum(nil)

	return sum
}

// convertEndianes changes the endianess of given data
func convertEndianess(src []byte, dst []byte) error {
	if len(src) != len(dst) {
		return fmt.Errorf("source and destination slices must be of the same length")
	}
	for i := range src {
		dst[len(src)-1-i] = src[i]
	}
	return nil
}
