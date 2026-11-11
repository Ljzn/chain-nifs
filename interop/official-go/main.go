// Independent command; wallet functions are exact upstream extracts.
package main

import (
	"blocknet/wallet"
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func decode(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func a32(s string) (a [32]byte) {
	b := decode(s)
	if len(b) != 32 {
		panic("expected 32 bytes")
	}
	copy(a[:], b)
	return
}
func must(b bool) {
	if !b {
		panic("cross verification mismatch")
	}
}

type vector struct {
	Index         int
	Amount        uint64
	Shared        string `json:"shared_sender_hex"`
	Blinding      string `json:"blinding_raw_hex"`
	Encrypted     string `json:"encrypted_amount_hex"`
	Memo          string `json:"memo_hex"`
	EncryptedMemo string `json:"encrypted_memo_hex"`
}

func fixture(raw []byte) {
	var f struct {
		Stealth struct {
			Seed         string `json:"wallet_seed64_hex"`
			SpendSeed    string `json:"spend_seed_hex"`
			ViewSeed     string `json:"view_seed_hex"`
			SpendPrivate string `json:"spend_private_hex"`
			SpendPublic  string `json:"spend_public_hex"`
			ViewPrivate  string `json:"view_private_hex"`
			ViewPublic   string `json:"view_public_hex"`
			Outputs      []vector
		}
	}
	if e := json.Unmarshal(raw, &f); e != nil {
		panic(e)
	}
	s := f.Stealth
	keys, e := wallet.DeriveKeysFromSeed(decode(s.Seed), func(seed [32]byte) ([32]byte, [32]byte, error) {
		switch seed {
		case a32(s.SpendSeed):
			return a32(s.SpendPrivate), a32(s.SpendPublic), nil
		case a32(s.ViewSeed):
			return a32(s.ViewPrivate), a32(s.ViewPublic), nil
		default:
			panic("unexpected seed split")
		}
	})
	if e != nil {
		panic(e)
	}
	must(keys.SpendPubKey == a32(s.SpendPublic) && keys.ViewPubKey == a32(s.ViewPublic))
	for _, o := range s.Outputs {
		b := wallet.DeriveBlinding(a32(o.Shared), o.Index)
		must(b == a32(o.Blinding))
		var encrypted [8]byte
		copy(encrypted[:], decode(o.Encrypted))
		must(wallet.DecryptAmount(encrypted, b, o.Index) == o.Amount)
		var memo [128]byte
		copy(memo[:], decode(o.EncryptedMemo))
		plain, valid := wallet.DecryptMemo(memo, a32(o.Shared), o.Index)
		must(valid && bytes.Equal(plain, decode(o.Memo)))
	}
	fmt.Println(`{"valid":true,"oracle":"official-go-wallet-extracts"}`)
}

type cursor struct {
	raw []byte
	off int
}

func (c *cursor) take(n int) []byte {
	if n < 0 || n > len(c.raw)-c.off {
		panic("truncated wire")
	}
	b := c.raw[c.off : c.off+n]
	c.off += n
	return b
}
func (c *cursor) u32() int { return int(binary.LittleEndian.Uint32(c.take(4))) }
func wire(raw []byte) map[string]any {
	c := cursor{raw: raw}
	must(c.take(1)[0] == 1)
	c.take(32)
	ni, no := c.u32(), c.u32()
	must(ni >= 1 && ni <= 16 && no >= 1 && no <= 16)
	fee := binary.LittleEndian.Uint64(c.take(8))
	for i := 0; i < no; i++ {
		c.take(200)
		np := c.u32()
		must(np <= 1024)
		c.take(np)
	}
	signing := sha3.Sum256(raw[:c.off])
	for i := 0; i < ni; i++ {
		ki, po := c.take(32), c.take(32)
		must(c.u32() == 16)
		c.take(1024)
		must(c.u32() == 1120)
		sig := c.take(1120)
		must(bytes.Equal(ki, sig[1056:1088]) && bytes.Equal(po, sig[1088:1120]))
	}
	must(c.off == len(raw))
	txid := sha3.Sum256(raw)
	return map[string]any{"valid": true, "signing_hash_hex": hex.EncodeToString(signing[:]), "txid_hex": hex.EncodeToString(txid[:]), "inputs": ni, "outputs": no, "fee": fee}
}
func main() {
	b, e := io.ReadAll(os.Stdin)
	if e != nil {
		panic(e)
	}
	if len(os.Args) > 1 && os.Args[1] == "wire" {
		var v struct {
			Payments []struct {
				Raw string `json:"raw_hex"`
			}
		}
		if e = json.Unmarshal(b, &v); e != nil {
			panic(e)
		}
		out := []map[string]any{}
		for _, p := range v.Payments {
			out = append(out, wire(decode(p.Raw)))
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"payments": out})
		return
	}
	fixture(b)
}
