package btcman

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xPolygon/cdk/btcman/indexer"
	"github.com/0xPolygon/cdk/log"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Client is the btc client that interacts with th btc chain
type Client struct {
	logger                   *log.Logger
	keychain                 Keychainer
	netParams                *chaincfg.Params
	cfg                      Config
	address                  *btcutil.Address
	IndexerClient            indexer.Indexerer
	consolidationStopChannel chan struct{}
}

func NewClient(cfg Config, logger *log.Logger) (Clienter, error) {
	logger.Debug("Creating btcman")
	isValid := IsValidBtcConfig(&cfg)
	if !isValid {
		logger.Fatal("Missing required BTC values")
	}

	// Check if the network is valid
	var network chaincfg.Params
	switch cfg.Net {
	case "mainnet":
		network = chaincfg.MainNetParams
	case "testnet":
		network = chaincfg.TestNet3Params
	case "regtest":
		network = chaincfg.RegressionNetParams
	default:
		err := errors.New("invalid network")
		return nil, err
	}

	// Get address from the private key
	address, err := indexer.PrivateKeyToAddress(cfg.PrivateKey, &network)
	if err != nil {
		logger.Fatal(err)
	}

	indexer := indexer.NewIndexer(cfg.EnableIndexerDebug, logger)
	indexer.Start(fmt.Sprintf("%s:%s", cfg.IndexerHost, cfg.IndexerPort))

	// TODO: check if balance > 0?

	consolidateTxFee := float64(cfg.ConsolidationTransactionFee)

	consolidationInterval := time.Second * time.Duration(cfg.ConsolidationInterval)
	ticker := time.NewTicker(consolidationInterval)
	stopChannel := make(chan struct{})

	keychain, err := NewKeychain(cfg.PrivateKey, indexer, &network, logger)
	if err != nil {
		logger.Fatal(err)
	}

	btcman := Client{
		logger:                   logger,
		keychain:                 keychain,
		cfg:                      cfg,
		netParams:                &network,
		address:                  &address,
		IndexerClient:            indexer,
		consolidationStopChannel: stopChannel,
	}

	go func() {
		for {
			select {
			case <-btcman.consolidationStopChannel:
				ticker.Stop()
				return
			case <-ticker.C:
				logger.Debug("Trying to consolidate")
				utxos, err := btcman.listUnspent()
				if err != nil {
					logger.Error(err)
				}

				btcman.consolidateUTXOS(utxos, consolidateTxFee, cfg.MinUtxoConsolidationAmount)
			}
		}
	}()

	return &btcman, nil
}

// Shutdown closes the RPC client
func (client *Client) Shutdown() {
	close(client.consolidationStopChannel)
	client.IndexerClient.Disconnect()
}

// getUTXO returns a UTXO spendable by address, consolidates the address utxo set if needed
func (client *Client) getUTXO() (*indexer.UTXO, error) {
	utxos, err := client.listUnspent()
	if err != nil {
		return nil, err
	}
	if len(utxos) == 0 {
		return nil, fmt.Errorf("there are no UTXOs")
	}

	utxoIndex := client.getIndexOfUtxoAboveThreshold(float64(client.cfg.UtxoThreshold), utxos)
	if utxoIndex == -1 {
		return nil, fmt.Errorf("can't find utxo to inscribe")
	}

	utxo := utxos[utxoIndex]

	client.logger.Info("UTXO for address was found")
	return utxo, nil
}

// consolidateUTXOS combines multiple utxo in one if the utxos are under a specific threshold and over a specific count
func (client *Client) consolidateUTXOS(utxos []*indexer.UTXO, consolidationFee float64, minUtxoCountConsolidate int) {
	if len(utxos) == 0 {
		client.logger.Info("Address has zero utxos.. skipping consolidation")
		return
	}

	var inputs []btcjson.TransactionInput
	dustAmount := btcutil.Amount(546)
	totalAmount := btcutil.Amount(0)

	for _, utxo := range utxos {
		amount := btcutil.Amount(utxo.Value)
		thresholdAmount := btcutil.Amount(float64(client.cfg.UtxoThreshold))
		if amount < thresholdAmount && amount > dustAmount {
			inputs = append(inputs, btcjson.TransactionInput{
				Txid: utxo.TxHash,
				Vout: uint32(utxo.TxPos),
			})
			client.logger.Debugf("Adding utxo %s with amount %d", utxo.TxHash, amount)
			totalAmount += amount
		}
	}

	if len(inputs) < minUtxoCountConsolidate || totalAmount <= btcutil.Amount(consolidationFee) {
		client.logger.Infof("Not enough UTXOs under the specified amount to consolidate. [%d/%d utoxs under %f]", len(inputs), minUtxoCountConsolidate, float64(client.cfg.UtxoThreshold))
		return
	}

	client.logger.Infof("Consolidating %d utxos with total amount %d", len(inputs), totalAmount)

	outputAmount := totalAmount - btcutil.Amount(consolidationFee*(float64(len(inputs))*0.1))

	rawTx, err := client.createRawTransaction(inputs, &outputAmount, client.address)
	if err != nil {
		client.logger.Errorf("error creating raw transaction: %v", err)
		return
	}

	err = client.keychain.SignTransaction(rawTx, client.IndexerClient)
	if err != nil {
		client.logger.Errorf("error signing raw transaction: %v", err)
		return
	}

	txHash, err := client.IndexerClient.SendTransaction(context.Background(), rawTx)
	if err != nil {
		client.logger.Errorf("error sending transaction: %v", err)
		return
	}
	client.logger.Infof("UTXOs consolidated successfully: %s", txHash)
}

// getUtxoAboveThreshold returns the index of utxo over a specific threshold from a utxo set, if doesn't exist returns -1
func (client *Client) getIndexOfUtxoAboveThreshold(threshold float64, utxos []*indexer.UTXO) int {
	for index, utxo := range utxos {
		if float64(utxo.Value) >= threshold {
			return index
		}
	}
	return -1
}

// createInscriptionRequest cretes the request for the insription with the inscription data
func (client *Client) createInscriptionRequest(data []byte) (*InscriptionRequest, error) {
	utxo, err := client.getUTXO()
	if err != nil {
		client.logger.Errorf("Can't find utxo %s", err)
		return nil, err
	}

	commitTxOutPoint := new(wire.OutPoint)
	inTxid, err := chainhash.NewHashFromStr(utxo.TxHash)
	if err != nil {
		client.logger.Error("Failed to create inscription request")
		return nil, err
	}

	commitTxOutPoint = wire.NewOutPoint(inTxid, uint32(utxo.TxPos))

	dataList := make([]InscriptionData, 0)

	dataList = append(dataList, InscriptionData{
		ContentType: "application/octet-stream",
		Body:        data,
		Destination: (*client.address).String(),
	})

	request := InscriptionRequest{
		CommitTxOutPointList: []*wire.OutPoint{commitTxOutPoint},
		CommitFeeRate:        3,
		FeeRate:              2,
		DataList:             dataList,
		SingleRevealTxOnly:   true,
		// RevealOutValue:       500,
	}
	return &request, nil
}

// createInscriptionTool returns a new inscription tool struct
func (client *Client) createInscriptionTool(message []byte) (*InscriptionTool, error) {
	request, err := client.createInscriptionRequest(message)
	if err != nil {
		client.logger.Errorf("Failed to create inscription request: %s", err)
		return nil, err
	}

	tool, err := NewInscriptionTool(client.netParams, request, client.IndexerClient, client.keychain)
	if err != nil {
		client.logger.Errorf("Failed to create inscription tool: %s", err)
		return nil, err
	}
	return tool, nil
}

// Inscribe creates an inscription of data into a btc transaction
func (client *Client) Inscribe(data []byte) error {
	tool, err := client.createInscriptionTool(data)
	if err != nil {
		client.logger.Errorf("Can't create inscription tool: %s", err)
		return err
	}

	commitTxHash, revealTxHashList, inscriptions, fees, err := tool.Inscribe()
	if err != nil {
		client.logger.Errorf("send tx err, %v", err)
		return err
	}
	revealTxHash := revealTxHashList[0]
	inscription := inscriptions[0]

	client.logger.Infof("CommitTxHash: %s", commitTxHash.String())
	client.logger.Infof("RevealTxHash: %s", revealTxHash.String())
	client.logger.Infof("Inscription: %s", inscription)
	client.logger.Infof("Fees: %d", fees)

	return nil
}

// DecodeInscription reads the inscribed message from BTC by a transaction hash
func (client *Client) DecodeInscription() (string, error) {
	height, err := client.getBlockchainHeigth()
	if err != nil {
		return "", err
	}

	revealTx, err := client.IndexerClient.
		GetLastInscribedTransactionByPublicKey(context.Background(), client.keychain.GetPublicKey(), height, float64(client.cfg.UtxoThreshold))
	if err != nil {
		switch err.(type) {
		case indexer.NoInscription:
			log.Warn(err)
			return err.Error(), nil
		default:
			log.Error(err)
		}
		return "", err
	}

	tx, err := client.getTransaction(revealTx.TxHash)
	if err != nil {
		return "", err
	}
	inscriptionMessage, err := client.getInscriptionMessage(tx.Hex)
	if err != nil {
		return "", err
	}

	disasm, err := txscript.DisasmString(inscriptionMessage)
	if err != nil {
		return "", err
	}

	proof := strings.ReplaceAll(disasm, " ", "")

	return proof, nil
}

// getTransaction returns a transaction from BTC by a transaction hash
func (client *Client) getTransaction(txid string) (*btcjson.GetTransactionResult, error) {
	indexerResponse, err := client.IndexerClient.GetTransaction(context.Background(), txid, false)
	if err != nil {
		return nil, err
	}
	return &btcjson.GetTransactionResult{
		Hex: indexerResponse.Hex,
	}, nil
}

// getInscriptionMessage returns the raw inscribed message from the transaction
func (client *Client) getInscriptionMessage(txHex string) ([]byte, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		client.logger.Errorf("Error decoding hex string: %s", err)
		return nil, err
	}
	var targetTx wire.MsgTx

	err = targetTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		client.logger.Infof("Error deserializing transaction: %s", err)
		return nil, err
	}
	if len(targetTx.TxIn) < 1 || len(targetTx.TxIn[0].Witness) < 2 {
		client.logger.Infof("Error getting witness data: %s\n", err)
		return nil, err
	}
	inscriptionHex := hex.EncodeToString(targetTx.TxIn[0].Witness[1])

	const (
		utfMarker       = "6170706c69636174696f6e2f6f637465742d73747265616d" // application/octet-stream
		utfMarkerLength = 48
	)

	// Get the message from the inscription
	markerIndex := strings.Index(inscriptionHex, utfMarker)
	if markerIndex == -1 {
		return nil, fmt.Errorf("inscription hex is invalid")
	}
	messageIndex := markerIndex + utfMarkerLength

	messageHex := inscriptionHex[messageIndex : len(inscriptionHex)-2]
	decodedBytes, err := hex.DecodeString(messageHex)
	if err != nil {
		client.logger.Errorf("Error decoding hex string: %s", err)
		return nil, err
	}
	return decodedBytes, nil
}

// getBlockchainHeigth returns the current height of the btc blockchain
func (client *Client) getBlockchainHeigth() (int32, error) {
	blockChainInfo, err := client.IndexerClient.GetBlockchainInfo(context.Background())
	if err != nil {
		return -1, err
	}
	return blockChainInfo.Height, nil
}

// TODO: when called, check if len is > 0
// listUnspent returns a list of unsent utxos filtered by address
func (client *Client) listUnspent() ([]*indexer.UTXO, error) {
	indexerResponse, err := client.IndexerClient.ListUnspent(context.Background(), client.keychain.GetPublicKey())
	if err != nil {
		return nil, err
	}
	blockchainHeight, err := client.getBlockchainHeigth()
	if err != nil {
		return nil, err
	}

	// TODO change and move to config when no longer using coinbase transactions for testing
	requiredCoinbaseConfirmations := int32(100)
	utxos := []*indexer.UTXO{}
	for _, r := range indexerResponse {
		// blockchain height - transacton block height + 1 in order to count the block of the transaction
		confirmations := blockchainHeight - int32(r.Height) + 1
		if confirmations > requiredCoinbaseConfirmations {
			utxos = append(utxos, r)

		}
	}

	return utxos, nil
}

// createRawTransaction returns an unsigned transaction
func (client *Client) createRawTransaction(inputs []btcjson.TransactionInput, outputAmount *btcutil.Amount, outputAddress *btcutil.Address) (*wire.MsgTx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	for _, input := range inputs {
		hash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing txid: %v", err)
		}

		outputIndex := input.Vout
		txIn := wire.NewTxIn(wire.NewOutPoint(hash, uint32(outputIndex)), nil, nil)
		tx.AddTxIn(txIn)
	}
	pubKeyHash := (*outputAddress).ScriptAddress()
	witnessProgram := append([]byte{0x00, 0x14}, pubKeyHash...)

	txOut := wire.NewTxOut(int64(*outputAmount), witnessProgram)
	tx.AddTxOut(txOut)

	return tx, nil
}
