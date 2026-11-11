package wallet
import("crypto/sha3";"encoding/binary")
// encryptAmount encrypts an amount using the blinding factor as shared secret
// Format: amount XOR first 8 bytes of Hash("amount" || blinding || output_index)
func encryptAmount(amount uint64, blinding [32]byte, outputIndex int) [8]byte {
	mask := amountMask(blinding, outputIndex)

	var amountBytes [8]byte
	binary.LittleEndian.PutUint64(amountBytes[:], amount)

	var encrypted [8]byte
	for i := 0; i < 8; i++ {
		encrypted[i] = amountBytes[i] ^ mask[i]
	}
	return encrypted
}

// DecryptAmount decrypts an encrypted amount using the blinding factor
func DecryptAmount(encrypted [8]byte, blinding [32]byte, outputIndex int) uint64 {
	mask := amountMask(blinding, outputIndex)

	var amountBytes [8]byte
	for i := range 8 {
		amountBytes[i] = encrypted[i] ^ mask[i]
	}
	return binary.LittleEndian.Uint64(amountBytes[:])
}

func amountMask(blinding [32]byte, outputIndex int) [32]byte {
	const tag = "blocknet_amount"
	var outputIndexBytes [4]byte
	binary.LittleEndian.PutUint32(outputIndexBytes[:], uint32(outputIndex))

	// sha3.Sum256 never fails; build explicit input bytes to avoid unchecked Write() errors.
	b := make([]byte, 0, len(tag)+32+4)
	b = append(b, tag...)
	b = append(b, blinding[:]...)
	b = append(b, outputIndexBytes[:]...)
	return sha3.Sum256(b)
}
