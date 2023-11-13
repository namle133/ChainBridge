module github.com/ChainSafe/ChainBridge

go 1.15

require (
	github.com/ChainSafe/chainbridge-substrate-events v0.0.0-20200715141113-87198532025e
	github.com/ChainSafe/chainbridge-utils v1.0.6
	github.com/ChainSafe/log15 v1.0.0
	github.com/awnumar/memguard v0.22.3
	github.com/centrifuge/go-substrate-rpc-client v2.0.0+incompatible
	github.com/deckarep/golang-set v1.7.1 // indirect
	github.com/ethereum/go-ethereum v1.10.8
	github.com/prometheus/client_golang v1.4.1
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sys v0.14.0 // indirect
)

replace (
	github.com/ChainSafe/chainbridge-utils v1.0.6 => github.com/ChainVerse-Team/chainbridge-utils v0.0.3-alpha
	github.com/awnumar/memguard v0.22.3 => github.com/ChainVerse-Team/memguard v0.0.1-beta
)
