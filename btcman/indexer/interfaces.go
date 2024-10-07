package indexer 

import "context"

type Indexerer interface {
	Start(string)
	ListUnspent(context.Context, string) ([]*Transaction, error)
	GetTransaction(context.Context, string, bool) (*GetTransaction, error)
	Disconnect()
}
