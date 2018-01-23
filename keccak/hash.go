package keccak

import (
	"encoding/hex"
)

func ShaHex256(m []byte) string {
	return hex.EncodeToString(Sha256(m))
}

func Sha256(m []byte) []byte {
	return keccak(512, []byte(m), 256, DOMAIN_SHA3)
}

func Keccak256(m []byte) []byte {
	return keccak(512, []byte(m), 256, DOMAIN_NONE)
}

func KeccakHex256(m []byte) string {
	return hex.EncodeToString(Keccak256(m))
}
