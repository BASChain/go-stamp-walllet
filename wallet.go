package stamp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pborman/uuid"
	"io/ioutil"
)

const (
	version = 1
)

type Wallet interface {
	String() string
	Address() common.Address
	Open(auth string) bool
	SaveToPath(path string) error
	SignJson(v interface{}) ([]byte, error)
	Sign(v []byte) ([]byte, error)
	ExportEth(auth, eAuth, path string) error
}

type SWallet struct {
	Version    int                 `json:"version"`
	Addr       common.Address      `json:"address"`
	Crypto     keystore.CryptoJSON `json:"crypto"`
	PrivateKey *ecdsa.PrivateKey   `json:"-"`
}

func NewWallet(auth string) (Wallet, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyBytes := math.PaddedBigBytes(privateKeyECDSA.D, 32)
	cryptoStruct, err := keystore.EncryptDataV3(keyBytes, []byte(auth), keystore.LightScryptN, keystore.LightScryptP)
	if err != nil {
		return nil, err
	}

	s := &SWallet{
		Version:    version,
		Addr:       crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		Crypto:     cryptoStruct,
		PrivateKey: privateKeyECDSA,
	}
	return s, nil
}

func WalletOfJson(jsonStr string) (Wallet, error) {
	sw := &SWallet{}
	if err := json.Unmarshal([]byte(jsonStr), sw); err != nil {
		return nil, err
	}
	return sw, nil
}

func WalletOfPath(path string) (Wallet, error) {
	jsonStr, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sw := &SWallet{}
	if err := json.Unmarshal(jsonStr, sw); err != nil {
		return nil, err
	}
	return sw, nil
}

func (sw *SWallet) Address() common.Address {
	return sw.Addr
}

func (sw *SWallet) String() string {
	j, _ := json.MarshalIndent(sw, "", "\t")
	return string(j)
}

func (sw *SWallet) Open(auth string) bool {
	if sw.PrivateKey != nil {
		return true
	}
	keyBytes, err := keystore.DecryptDataV3(sw.Crypto, auth)
	if err != nil {
		return false
	}

	sw.PrivateKey = crypto.ToECDSAUnsafe(keyBytes)
	return true
}

func (sw *SWallet) SaveToPath(path string) error {
	j, _ := json.MarshalIndent(sw, "", "\t")
	return ioutil.WriteFile(path, j, 0644)
}

func (sw *SWallet) SignJson(v interface{}) ([]byte, error) {
	rawBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256(rawBytes)
	return crypto.Sign(hash, sw.PrivateKey)
}

func (sw *SWallet) Sign(v []byte) ([]byte, error) {
	return crypto.Sign(v, sw.PrivateKey)
}

func (sw *SWallet) ExportEth(auth, eAuth, path string) error {

	keyBytes, err := keystore.DecryptDataV3(sw.Crypto, auth)
	if err != nil {
		panic(err)
	}
	key := crypto.ToECDSAUnsafe(keyBytes)

	ethKey := &keystore.Key{
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		PrivateKey: key,
	}

	id := uuid.NewRandom()
	ethKey.Id = make([]byte, len(id))
	copy(ethKey.Id, id)

	newJson, err := keystore.EncryptKey(ethKey, eAuth, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return fmt.Errorf("error encrypting with new password: %v", err)
	}
	if err := ioutil.WriteFile(path, newJson, 0644); err != nil {
		return fmt.Errorf("error writing new keyfile to disk: %v", err)
	}
	return nil
}

func VerifyJsonSig(mainAddr common.Address, sig []byte, v interface{}) bool {
	return mainAddr == RecoverJson(sig, v)
}

func VerifyAbiSig(mainAddr common.Address, sig []byte, msg []byte) bool {
	signer, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}

	return mainAddr == crypto.PubkeyToAddress(*signer)
}

func RecoverJson(sig []byte, v interface{}) common.Address {
	data, err := json.Marshal(v)
	if err != nil {
		return common.Address{}
	}
	hash := crypto.Keccak256(data)
	signer, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}
	}
	address := crypto.PubkeyToAddress(*signer)
	return address
}
