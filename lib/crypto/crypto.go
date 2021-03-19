package crypto

import (
	"golang.org/x/crypto/sha3"
)

const hashSize = 32

// Hash takes in []byte inputs and outputs a hash value
func Hash(ms ...[]byte) []byte {
	h := sha3.NewShake128() // TODO: do we want to change the function used?
	//NOTE: Google KT uses sha256.Sum256 -- Yuncong

	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, hashSize)
	h.Read(ret)

	return ret
}
