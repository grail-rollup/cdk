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
	"github.com/0xPolygonHermez/zkevm-node/log"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type Client struct {
	BtcClient                BtcRpcClienter
	netParams                *chaincfg.Params
	cfg                      Config
	address                  btcutil.Address
	publicKey                string
	lastRevealTransaction    string
	IndexerClient            indexer.Indexerer
	consolidationStopChannel chan struct{}
	utxoThreshold            float64
	consolidationFee         float64
}

func NewClient(cfg Config) (Clienter, error) {
	log.Debug("Creating btcman")
	log.Info("Creating btcman")
	isValid := IsValidBtcConfig(&cfg)
	if !isValid {
		log.Fatal("Missing required BTC values")
	}

	// Create the RPC client
	rpcUrl := fmt.Sprintf("%s:%s/wallet/%s", cfg.Host, cfg.Port, cfg.WalletName)
	rpcConfig := &rpcclient.ConnConfig{
		Host:         rpcUrl,
		User:         cfg.RpcUser,
		Pass:         cfg.RpcPass,
		HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
		DisableTLS:   true, // Bitcoin core does not provide TLS by default
	}

	client, err := rpcclient.New(rpcConfig, nil)
	if err != nil {
		return nil, err
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

	// Derive address from the private key
	descriptor := fmt.Sprintf("wpkh(%s)", cfg.PrivateKey)
	descriptorInfo, err := client.GetDescriptorInfo(descriptor)
	if err != nil {
		log.Fatal(err)
	}
	checksum := descriptorInfo.Checksum

	result, err := client.DeriveAddresses(fmt.Sprintf("%s#%s", descriptor, checksum), nil)
	if err != nil {
		log.Fatal(err)
	}
	address := (*result)[0]
	decodedAddress, err := btcutil.DecodeAddress(address, &network)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := privateToPublicKey(cfg.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	indexer := indexer.NewIndexer(cfg.EnableIndexerDebug)
	indexer.Start(cfg.IndexerHost)

	// TODO: check if balance > 0?

	utxoThreshold := float64(cfg.UtxoThreshold)
	consolidateTxFee := float64(cfg.ConsolidationTransactionFee)

	consolidationInterval := time.Second * time.Duration(cfg.ConsolidationInterval)
	ticker := time.NewTicker(consolidationInterval)

	stopChannel := make(chan struct{})

	btcman := Client{
		BtcClient:                client,
		cfg:                      cfg,
		netParams:                &network,
		address:                  decodedAddress,
		publicKey:                publicKey,
		IndexerClient:            indexer,
		utxoThreshold:            utxoThreshold,
		consolidationFee:         consolidateTxFee,
		consolidationStopChannel: stopChannel,
	}

	go func() {
		for {
			select {
			case <-btcman.consolidationStopChannel:
				ticker.Stop()
				return
			case <-ticker.C:
				log.Info("Trying to consolidate")
				utxos, err := btcman.listUnspent()
				if err != nil {
					log.Error(err)
				}

				btcman.consolidateUTXOS(utxos, btcman.utxoThreshold, btcman.consolidationFee, &btcman.address)
			}
		}
	}()

	return &btcman, nil
}

// Shutdown closes the RPC client
func (client *Client) Shutdown() {
	close(client.consolidationStopChannel)
	client.IndexerClient.Disconnect()
	client.BtcClient.Shutdown()
}

// getUTXO returns a UTXO spendable by address, consolidates the address utxo set if needed
func (client *Client) getUTXO() (*btcjson.ListUnspentResult, error) {
	utxos, err := client.listUnspent()
	if err != nil {
		return nil, err
	}

	if len(utxos) == 0 {
		return nil, fmt.Errorf("there are no UTXOs for address %s", client.address)
	}

	utxoIndex := client.getIndexOfUtxoAboveThreshold(client.utxoThreshold, utxos)
	if utxoIndex == -1 {
		return nil, fmt.Errorf("can't find utxo to inscribe")
	}

	utxo := utxos[utxoIndex]

	log.Infof("UTXO for address %s was found", client.address)
	return &utxo, nil
}

// consolidateUTXOS combines multiple utxo in one if the utxos are under a specific threshold and over a specific count
func (client *Client) consolidateUTXOS(utxos []btcjson.ListUnspentResult, threshold, consolidationTxFee float64, address *btcutil.Address) {
	if len(utxos) == 0 {
		log.Info("Address has zero utxos.. skipping consolidation")
		return
	}
	minUtxoCount := 10

	var inputs []btcjson.TransactionInput
	dustAmount := btcutil.Amount(546)
	totalAmount := btcutil.Amount(0)
	log.Infof("UTXO count: %d", len(utxos))
	for _, utxo := range utxos {

		amount := btcutil.Amount(utxo.Amount)
		thresholdAmount := btcutil.Amount(threshold)
		if amount < thresholdAmount && amount > dustAmount {
			inputs = append(inputs, btcjson.TransactionInput{
				Txid: utxo.TxID,
				Vout: utxo.Vout,
			})
			log.Infof("Adding utxo %s with amount %d", utxo.TxID, amount)
			totalAmount += amount
		}
	}

	if len(inputs) < minUtxoCount || totalAmount <= btcutil.Amount(consolidationTxFee) {
		log.Infof("Not enough UTXOs under the specified amount to consolidate. [%d/%d utoxs under %f]", len(inputs), minUtxoCount, threshold)
		return
	}

	log.Infof("Consolidating %d utxos with total amount %d", len(inputs), totalAmount)

	outputs := map[btcutil.Address]btcutil.Amount{
		*address: totalAmount - btcutil.Amount(consolidationTxFee),
	}

	rawTx, err := client.BtcClient.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		log.Errorf("error creating raw transaction: %v", err)
		return
	}

	signedTx, _, err := client.BtcClient.SignRawTransactionWithWallet(rawTx)
	if err != nil {
		log.Errorf("error signing raw transaction: %v", err)
		return
	}

	txHash, err := client.BtcClient.SendRawTransaction(signedTx, false)
	if err != nil {
		log.Errorf("error sending transaction: %v", err)
		return
	}
	log.Infof("UTXOs consolidated successfully: %s", txHash)
}

// getUtxoAboveThreshold returns the index of utxo over a specific threshold from a utxo set, if doesn't exist returns -1
func (client *Client) getIndexOfUtxoAboveThreshold(threshold float64, utxos []btcjson.ListUnspentResult) int {
	for index, utxo := range utxos {
		if utxo.Amount >= float64(threshold) {

			return index
		}
	}
	return -1
}

// createInscriptionRequest cretes the request for the insription with the inscription data
func (client *Client) createInscriptionRequest(data []byte) (*InscriptionRequest, error) {
	utxo, err := client.getUTXO()
	if err != nil {
		log.Errorf("Can't find utxo %s", err)
		return nil, err
	}

	commitTxOutPoint := new(wire.OutPoint)
	inTxid, err := chainhash.NewHashFromStr(utxo.TxID)
	if err != nil {
		log.Error("Failed to create inscription request")
		return nil, err
	}

	commitTxOutPoint = wire.NewOutPoint(inTxid, utxo.Vout)

	dataList := make([]InscriptionData, 0)

	dataList = append(dataList, InscriptionData{
		ContentType: "application/octet-stream",
		Body:        data,
		Destination: client.address.String(),
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
		log.Errorf("Failed to create inscription request: %s", err)
		return nil, err
	}

	tool, err := NewInscriptionTool(client.netParams, client.BtcClient, request)
	if err != nil {
		log.Errorf("Failed to create inscription tool: %s", err)
		return nil, err
	}
	return tool, nil
}

func (client *Client) Inscribe(data []byte) (string, error) {
	tool, err := client.createInscriptionTool(data)
	if err != nil {
		log.Errorf("Can't create inscription tool: %s", err)
		return "", err
	}

	commitTxHash, revealTxHashList, inscriptions, fees, err := tool.Inscribe()
	if err != nil {
		log.Errorf("send tx err, %v", err)
		return "", err
	}
	revealTxHash := revealTxHashList[0]
	inscription := inscriptions[0]

	log.Infof("CommitTxHash: %s", commitTxHash.String())
	log.Infof("RevealTxHash: %s", revealTxHash.String())
	log.Infof("Inscription: %s", inscription)
	log.Infof("Fees: %d", fees)

	client.lastRevealTransaction = revealTxHash.String()
	return client.lastRevealTransaction, nil
}

// DecodeInscription reads the inscribed message from a BTC by a transaction hash
func (client *Client) DecodeInscription() (string, error) {
	tx, err := client.getTransaction(client.lastRevealTransaction)
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
		log.Errorf("Error decoding hex string: %s", err)
		return nil, err
	}
	var targetTx wire.MsgTx

	err = targetTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		log.Infof("Error deserializing transaction: %s", err)
		return nil, err
	}
	if len(targetTx.TxIn) < 1 || len(targetTx.TxIn[0].Witness) < 2 {
		log.Infof("Error getting witness data: %s\n", err)
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
		log.Errorf("Error decoding hex string: %s", err)
		return nil, err
	}
	return decodedBytes, nil
}

func (client *Client) getBlockchainHeigth() (int32, error) {
	blockChainInfo, err := client.BtcClient.GetBlockChainInfo()
	if err != nil {
		return -1, err
	}
	return blockChainInfo.Blocks, nil
}

// TODO: when called, check if len is > 0
// listUnspent returns a list of unsent utxos filtered by address
func (client *Client) listUnspent() ([]btcjson.ListUnspentResult, error) {
	indexerResponse, err := client.IndexerClient.ListUnspent(context.Background(), client.publicKey)
	if err != nil {
		return nil, err
	}
	blockchainHeight, err := client.getBlockchainHeigth()
	if err != nil {
		return nil, err
	}
	// TODO change and move to config when no longer using coinbase transactions for testing

	requiredCoinbaseConfirmations := int32(100)
	utxos := []btcjson.ListUnspentResult{}
	for _, r := range indexerResponse {
		// blockchain height - transacton block height + 1 in order to count the block of the transaction
		confirmations := blockchainHeight - int32(r.Height) + 1
		if confirmations > requiredCoinbaseConfirmations {
			utxos = append(utxos, btcjson.ListUnspentResult{
				TxID:          r.Hash,
				Confirmations: int64(confirmations),
				Vout:          uint32(r.Pos),
				Amount:        float64(r.Value),
			})

		}
	}

	return utxos, nil
}
