package btcman

type Config struct {
	// Net is the type of network of the btc node
	Net string `mapstructure:"Net"`

	// PrivateKey is the private key for the btc node wallet
	PrivateKey string `mapstructure:"PrivateKey"`

	// IndexerHost is the host of the indexer server
	IndexerHost string `mapstructure:"IndexerHost"`

	// IndexerPort is the port of the indexer server
	IndexerPort string `mapstructure:"IndexerPort"`

	// ConsolidationInterval is the interval between checks for utxos consolidations, in seconds
	ConsolidationInterval int `mapstructure:"ConsolidationInterval"`

	// ConsolidationTransactionFee is the fee paid for the consolidation transaction, in satoshi
	ConsolidationTransactionFee int `mapstructure:"ConsolidationTransactionFee"`

	// UtxoThreshold is the the minimum amount of satoshis under which the UTXO is used for consolidation
	UtxoThreshold int `mapstructure:"UtxoThreshold"`

	// MinUtxoConsolidationAmount is the minimum number of UTXOS under the UtxoThreshold in order to perform a consolidation
	MinUtxoConsolidationAmount int `mapstructure:"MinUtxoConsolidationAmount"`

	// EnableIndexerDebug is a flag for enabling debuging messages in indexer client
	EnableIndexerDebug bool `mapstructure:"EnableIndexerDebug"`
}

func IsValidBtcConfig(cfg *Config) bool {
	return cfg.Net != "" &&
		cfg.PrivateKey != "" &&
		cfg.IndexerHost != "" &&
		cfg.IndexerPort != "" &&
		cfg.ConsolidationInterval != 0 &&
		cfg.ConsolidationTransactionFee != 0 &&
		cfg.UtxoThreshold != 0 &&
		cfg.MinUtxoConsolidationAmount != 0
}
