package stamp

import "github.com/ethereum/go-ethereum/common"

type Wallet interface {
	String() string
	Address() common.Address
}

type SWallet struct {
	Addr common.Address
}

func NewWallet(auth string) (Wallet, error) {
	s := &SWallet{}
	return s, nil
}

func (sw *SWallet) Address() common.Address {
	return sw.Addr
}

func (sw *SWallet) String() string {
	return ""
}
