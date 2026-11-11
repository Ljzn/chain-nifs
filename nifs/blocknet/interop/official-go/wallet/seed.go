package wallet
import "errors"
type StealthKeys struct {SpendPrivKey,SpendPubKey,ViewPrivKey,ViewPubKey [32]byte}
// DeriveKeysFromSeed derives spend and view keypairs from a 64-byte seed
// Returns: spendPriv, spendPub, viewPriv, viewPub
func DeriveKeysFromSeed(seed []byte, generateKeypair func(seed [32]byte) ([32]byte, [32]byte, error)) (*StealthKeys, error) {
	if len(seed) < 64 {
		return nil, errors.New("seed must be at least 64 bytes")
	}

	// Derive spend key from first 32 bytes
	var spendSeed [32]byte
	copy(spendSeed[:], seed[:32])
	spendPriv, spendPub, err := generateKeypair(spendSeed)
	if err != nil {
		return nil, err
	}

	// Derive view key from last 32 bytes
	var viewSeed [32]byte
	copy(viewSeed[:], seed[32:64])
	viewPriv, viewPub, err := generateKeypair(viewSeed)
	if err != nil {
		return nil, err
	}

	return &StealthKeys{
		SpendPrivKey: spendPriv,
		SpendPubKey:  spendPub,
		ViewPrivKey:  viewPriv,
		ViewPubKey:   viewPub,
	}, nil
}
