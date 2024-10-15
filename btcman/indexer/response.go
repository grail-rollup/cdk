package indexer

type UTXO struct {
	TxPos  int    `json:"tx_pos"`
	Value  int64  `json:"value"`
	TxHash string `json:"tx_hash"`
	Height int    `json:"height"`
}

type BlockChainInfo struct {
	Height int32  `json:"height"`
	Hex    string `json:"hex"`
}

type TxInfo struct {
	Height int32  `json:"height"`
	TxHash string `json:"tx_hash"`
	Fee    int32  `json:"fee"`
}
