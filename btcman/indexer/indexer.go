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

	"github.com/0xPolygonHermez/zkevm-node/log"
)

const delim = byte('\n')

var (
	ErrIndexerConnected = errors.New("indexer already connected")
	ErrIndexerShutdown  = errors.New("indexer has shutdown")
)

type container struct {
	content []byte
	err     error
}

type Indexer struct {
	transport *transport

	handlersLock sync.RWMutex
	handlers     map[uint64]chan *container

	pushHandlersLock sync.RWMutex
	pushHandlers     map[string][]chan *container

	errs chan error
	quit chan struct{}

	nextId  uint64
	isDebug bool
}

// NewIndexer creates a new indexerer.
func NewIndexer(isDebug bool) Indexerer {
	i := &Indexer{
		handlers:     make(map[uint64]chan *container),
		pushHandlers: make(map[string][]chan *container),

		errs:    make(chan error),
		quit:    make(chan struct{}),
		isDebug: isDebug,
	}

	return i
}

// Start the indexer goroutines
func (i *Indexer) Start(serverAddress string) {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	connectCancelationInterval := 3
	connectCtx, _ := context.WithTimeout(ctx, time.Second*time.Duration(connectCancelationInterval))
	if err := i.connect(connectCtx, serverAddress, nil); err != nil {
		fmt.Printf("connect node: %v", err)
		return
	}

	go func() {
		err := <-i.errors()
		log.Errorf("ran into error: %s", err)
		i.Disconnect()
	}()
	indexerPingInterval := 5
	go func() {
		for {
			if err := i.ping(ctx); err != nil {
				log.Fatal(err)
			}

			select {
			case <-time.After(time.Duration(indexerPingInterval) * time.Second):
			case <-ctx.Done():
				return
			}

		}
	}()
}

// errors returns any errors the node ran into while listening to messages.
func (i *Indexer) errors() <-chan error {
	return i.errs
}

// connect creates a new TCP connection to the specified address. If the TLS
// config is not nil, TLS is applied to the connection.
func (i *Indexer) connect(ctx context.Context, addr string, config *tls.Config) error {
	if i.transport != nil {
		return ErrIndexerConnected
	}

	transport, err := newTransport(ctx, addr, i.isDebug, config)
	if err != nil {
		return err
	}
	i.transport = transport

	listenCtx, cancel := context.WithCancel(context.Background())
	go func() {
		i.transport.listen(listenCtx)
	}()

	// Quit the transport listening once the node shuts down
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
			log.Infof("Transport is nil inside Indexer.listen(), exiting loop")
			return
		}

		select {
		case <-ctx.Done():
			if i.isDebug {
				log.Infof("indexer: listen: context finished, exiting loop")
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
				if i.transport.isDebug {
					log.Errorf("unmarshal received message failed: %v", err)
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
		log.Warn("WARNING: disconnecting indexer before transport is set up")
		return
	}

	if i.isDebug {
		log.Info("disconnecting indexer")
	}

	close(i.quit)

	i.transport.conn.Close()

	i.handlers = nil
	i.pushHandlers = nil
}

func (i *Indexer) ping(ctx context.Context) error {
	const method string = "server.ping"
	err := i.request(ctx, method, []interface{}{}, nil)
	log.Info("Pinging indexer server")
	return err
}

// GetTransaction returns a transaction by its transaction id
func (i *Indexer) GetTransaction(ctx context.Context, txID string, verbose bool) (*GetTransaction, error) {
	if !verbose {
		hex, err := i.blockchainTransactionGetNonVerbose(ctx, txID)
		if err != nil {
			return nil, err
		}

		return &GetTransaction{Hex: hex}, nil
	}
	const method string = "blockchain.transaction.get"
	resp := &struct {
		Result GetTransaction `json:"result"`
	}{}
	err := i.request(ctx, method, []interface{}{txID, verbose}, resp)
	if err != nil {
		return nil, err
	}

	return &resp.Result, nil
}

// blockchainTransactionGetNonVerbose returns a transaction by its transaction id
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

// ListUnspent returns a list of unspend utxos by a publicKey
func (i *Indexer) ListUnspent(ctx context.Context, publicKey string) ([]*Transaction, error) {
	const method string = "blockchain.scripthash.listunspent"
	resp := &struct {
		Result []*Transaction `json:"result"`
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
