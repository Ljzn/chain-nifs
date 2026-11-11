package wallet
import("crypto/sha3";"encoding/binary")
// DeriveBlinding derives a blinding factor from the shared secret and output index.
// blinding = Hash("blocknet_blinding" || shared_secret || output_index)
func DeriveBlinding(sharedSecret [32]byte, outputIndex int) [32]byte {
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))
	const tag = "blocknet_blinding"
	b := make([]byte, 0, len(tag)+len(sharedSecret)+len(outputIndexBytes))
	b = append(b, tag...)
	b = append(b, sharedSecret[:]...)
	b = append(b, outputIndexBytes[:]...)
	blinding := sha3.Sum256(b)

	// Reduce modulo the curve order to ensure it's a valid scalar
	// For Ristretto255, scalars are mod 2^252 + 27742317777372353535851937790883648493
	// The hash output is already 32 bytes, which is fine for this purpose
	// as the Rust side handles canonical reduction
	return blinding
}
