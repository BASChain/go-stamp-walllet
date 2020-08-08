package stamp

type Wallet interface {
	String() string
}

type SWallet struct {
}

func NewWallet(auth string) (Wallet, error) {
	return nil, nil
}
