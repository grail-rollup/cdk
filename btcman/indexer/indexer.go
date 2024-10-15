package indexer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xPolygon/cdk/log"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

const delim = byte('\n')

var (
	ErrIndexerConnected = errors.New("indexer already connected")
	ErrIndexerShutdown  = errors.New("indexer has shutdown")
)

type response struct {
	Id     uint64 `json:"id"`
	Method string `json:"method"`
	Error  any    `json:"error"`
}

type request struct {
	Id     uint64        `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type container struct {
	content []byte
	err     error
}

// Indexer comunicates with the btc indexer
type Indexer struct {
	logger           *log.Logger
	transport        *transport
	handlersLock     sync.RWMutex
	handlers         map[uint64]chan *container
	pushHandlersLock sync.RWMutex
	pushHandlers     map[string][]chan *container
	errs             chan error
	quit             chan struct{}
	nextId           uint64
	isDebug          bool
}

func NewIndexer(isDebug bool, logger *log.Logger) *Indexer {

	i := &Indexer{
		logger:       logger,
		handlers:     make(map[uint64]chan *container),
		pushHandlers: make(map[string][]chan *container),
		errs:         make(chan error),
		quit:         make(chan struct{}),
		isDebug:      isDebug,
	}

	return i
}

// Start initializes the indexer goroutines
func (i *Indexer) Start(serverAddress string) {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	connectCtx, _ := context.WithTimeout(ctx, time.Second*3)
	if err := i.connect(connectCtx, serverAddress, nil); err != nil {
		i.logger.Debugf("connect node: %v", err)
		return
	}

	go func() {
		err := <-i.errors()
		i.logger.Errorf("ran into error: %s", err)
		i.Disconnect()
	}()
	indexerPingInterval := 5
	go func() {
		for {
			if err := i.ping(ctx); err != nil {
				i.logger.Fatal(err)
			}

			select {
			case <-time.After(time.Duration(indexerPingInterval) * time.Second):
			case <-ctx.Done():
				return
			}

		}
	}()
}

// errors returns any errors the indexer ran into while listening to messages.
func (i *Indexer) errors() <-chan error {
	return i.errs
}

// connect creates a new TCP connection to the specified address. If the TLS
// config is not nil, TLS is applied to the connection.
func (i *Indexer) connect(ctx context.Context, addr string, config *tls.Config) error {
	if i.transport != nil {
		return ErrIndexerConnected
	}

	transport, err := newTransport(ctx, addr, config, i.logger, i.isDebug)
	if err != nil {
		return err
	}
	i.transport = transport

	listenCtx, cancel := context.WithCancel(context.Background())
	go func() {
		i.transport.listen(listenCtx)
	}()

	// Quit the transport listening once the indexer shuts down
	go func() {
		<-i.quit
		cancel()
	}()

	go i.listen(listenCtx)

	return nil
}

// listen processes messages from the server.
func (i *Indexer) listen(ctx context.Context) {
	for {
		if i.transport == nil {
			i.logger.Warn("Transport is nil inside Indexer.listen(), exiting loop")
			return
		}

		select {
		case <-ctx.Done():
			if i.isDebug {
				i.logger.Debug("indexer: listen: context finished, exiting loop")
			}
			return

		case err := <-i.transport.errors:
			i.errs <- fmt.Errorf("transport: %w", err)

		case bytes := <-i.transport.responses:
			result := &container{
				content: bytes,
			}

			msg := &response{}
			if err := json.Unmarshal(bytes, msg); err != nil {
				if i.isDebug {
					i.logger.Debugf("unmarshal received message failed: %v", err)
				}

				result.err = fmt.Errorf("unmarshal received message failed: %v", err)
			} else if msg.Error != nil {
				result.err = errors.New(fmt.Sprint(msg.Error))
			}

			// subscribe message if returned message with 'method' field
			if len(msg.Method) > 0 {
				i.pushHandlersLock.RLock()
				handlers := i.pushHandlers[msg.Method]
				i.pushHandlersLock.RUnlock()

				for _, handler := range handlers {
					select {
					case handler <- result:
					default:
					}
				}
			}

			i.handlersLock.RLock()
			c, ok := i.handlers[msg.Id]
			i.handlersLock.RUnlock()

			if ok {
				c <- result
			}
		}
	}
}

// request makes a request to the server and unmarshals the response into v.
func (i *Indexer) request(ctx context.Context, method string, params []interface{}, v interface{}) error {
	select {
	case <-i.quit:
		return ErrIndexerShutdown
	default:
	}

	msg := request{
		Id:     atomic.AddUint64(&i.nextId, 1),
		Method: method,
		Params: params,
	}
	bytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	bytes = append(bytes, delim)
	if err := i.transport.SendMessage(ctx, bytes); err != nil {
		return err
	}

	c := make(chan *container, 1)

	i.handlersLock.Lock()
	i.handlers[msg.Id] = c
	i.handlersLock.Unlock()

	var resp *container
	select {
	case resp = <-c:
	case <-ctx.Done():
		return ctx.Err()
	}

	if resp.err != nil {
		return resp.err
	}

	i.handlersLock.Lock()
	delete(i.handlers, msg.Id)
	i.handlersLock.Unlock()

	if v != nil {
		err = json.Unmarshal(resp.content, v)
		if err != nil {
			return err
		}
	}

	return nil
}

// Disconnect shuts down the indexer.
func (i *Indexer) Disconnect() {
	select {
	case <-i.quit:
		return

	default:
	}

	if i.transport == nil {
		i.logger.Warn("WARNING: disconnecting indexer before transport is set up")
		return
	}

	if i.isDebug {
		i.logger.Debug("disconnecting indexer")
	}

	close(i.quit)

	i.transport.conn.Close()

	i.handlers = nil
	i.pushHandlers = nil
}

// ping the server in order to keep the connection open
func (i *Indexer) ping(ctx context.Context) error {
	const method string = "server.ping"
	err := i.request(ctx, method, []interface{}{}, nil)
	log.Debug("Pinging indexer server")
	return err
}

// GetTransaction returns a transaction from the btc indexer
func (i *Indexer) GetTransaction(ctx context.Context, txID string, verbose bool) (*btcjson.TxRawResult, error) {
	if !verbose {
		hex, err := i.blockchainTransactionGetNonVerbose(ctx, txID)
		if err != nil {
			return nil, err
		}

		return &btcjson.TxRawResult{Hex: hex}, nil
	}
	const method string = "blockchain.transaction.get"
	resp := &struct {
		Result btcjson.TxRawResult `json:"result"`
	}{}
	err := i.request(ctx, method, []interface{}{txID, verbose}, resp)
	if err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// blockchainTransactionGetNonVerbose handles the nonverbose transaction request
func (i *Indexer) blockchainTransactionGetNonVerbose(ctx context.Context, txid string) (string, error) {
	const method string = "blockchain.transaction.get"
	resp := struct {
		Result string `json:"result"`
	}{}
	err := i.request(ctx, method, []interface{}{txid, false}, &resp)
	if err != nil {
		return "", err
	}

	return resp.Result, nil
}

// ListUnspent returns a list of unspent UTXOs by given publicKey
func (i *Indexer) ListUnspent(ctx context.Context, publicKey string) ([]*UTXO, error) {
	const method string = "blockchain.scripthash.listunspent"
	resp := &struct {
		Result []*UTXO `json:"result"`
	}{}
	scriptHash, err := publicKeyToScriptHash(publicKey)
	if err != nil {
		return nil, err
	}
	err = i.request(ctx, method, []interface{}{scriptHash}, resp)
	if err != nil {
		return nil, err
	}

	return resp.Result, nil
}

// SendTransaction broadcasts a transaction to the btc node
func (i *Indexer) SendTransaction(ctx context.Context, tx *wire.MsgTx) (string, error) {
	txHex, err := GetTxHex(tx)
	if err != nil {
		return "", err
	}

	const method string = "blockchain.transaction.broadcast"
	resp := &struct {
		Result string `json:"result"`
	}{}
	err = i.request(ctx, method, []interface{}{txHex}, resp)
	if err != nil {
		return "", err
	}
	return resp.Result, nil
}

// GetBlockchainInfo returns the latest information about the btc blockchain
func (i *Indexer) GetBlockchainInfo(ctx context.Context) (*BlockChainInfo, error) {
	const method string = "blockchain.headers.subscribe"
	resp := &struct {
		Result BlockChainInfo `json:"result"`
	}{}
	err := i.request(ctx, method, []interface{}{}, resp)
	if err != nil {
		return nil, err
	}
	return &resp.Result, nil
}

// GetLastInscribedTransactionByPublicKey returns the txInfo of the last reveal inscription transaction added in a block
func (i *Indexer) GetLastInscribedTransactionByPublicKey(ctx context.Context, publicKey string, blockchainHeight int32, utxoThreshold float64) (*TxInfo, error) {
	scriptHash, err := publicKeyToScriptHash(publicKey)
	if err != nil {
		return nil, err
	}
	const method = "blockchain.scripthash.get_history"
	resp := &struct {
		Result []TxInfo `json:"result"`
	}{}

	if err = i.request(ctx, method, []interface{}{scriptHash}, resp); err != nil {
		return nil, err
	}

	// get transactions only in last block
	transactionsInLastBlock := []TxInfo{}
	for _, tx := range resp.Result {
		if tx.Height == blockchainHeight {
			transactionsInLastBlock = append(transactionsInLastBlock, tx)
		}
	}

	for _, tx := range transactionsInLastBlock {

		rawTx, err := i.GetTransaction(ctx, tx.TxHash, true)
		if err != nil {
			return nil, err
		}
		amount := float64(0)
		for _, vout := range rawTx.Vout {
			amount += vout.Value
		}

		// get only the review transaction
		if amount*btcutil.SatoshiPerBitcoin < utxoThreshold {
			i.logger.Debugf("Tx: %s, Amount: %f, Threshold: %f", tx.TxHash, amount*btcutil.SatoshiPerBitcoin, utxoThreshold)
			return &tx, nil
		}
	}
	return nil, NewNoInscriptionError()
}
