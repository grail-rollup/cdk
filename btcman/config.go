package btcman

type Config struct {
	// Host is the rpc host of the btc node
	Host string `mapstructure:"Host"`

	// Port is the rpc port of the btc node
	Port string `mapstructure:"Port"`

	// Net is the type of network of the btc node
	Net string `mapstructure:"Net"`

	// WalletName is the wallet name of the btc node
	WalletName string `mapstructure:"WalletName"`

	// WalletPass is the password of the btc wallet for the node
	WalletPass string `mapstructure:"WalletPass"`

	// RpcUser is the username for the rpc service
	RpcUser string `mapstructure:"RpcUser"`

	// RpcPass is the password for the rpc service
	RpcPass string `mapstructure:"RpcPass"`

	// PrivateKey is the private key for the btc node wallet
	PrivateKey string `mapstructure:"PrivateKey"`

	// DisableTLS is a flat that disables the TLS
	DisableTLS bool `mapstructure:"DisableTLS"`

	// IndexerHost is the host of the indexer server
	IndexerHost string `mapstructure:"IndexerHost"`

	// ConsolidationInterval is the interval betwenn checks for utxos consolidations, in seconds
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
	return cfg.Host != "" &&
		cfg.Port != "" &&
		cfg.RpcUser != "" &&
		cfg.RpcPass != "" &&
		cfg.WalletName != "" &&
		cfg.PrivateKey != "" &&
		cfg.IndexerHost != "" &&
		cfg.ConsolidationInterval != 0 &&
		cfg.ConsolidationTransactionFee != 0 &&
		cfg.UtxoThreshold != 0 &&
		cfg.MinUtxoConsolidationAmount != 0
}
