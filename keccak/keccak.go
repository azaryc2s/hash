package keccak

import (
	"encoding/binary"
	"math/bits"
)

const (
	b            = 1600
	w            = 64
	DOMAIN_NONE  = 1
	DOMAIN_SHA3  = 0x06
	DOMAIN_SHAKE = 0x1f
)

var (
	rndc = [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}

	rotc = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
	piln = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}
)

func keccak160024(msg []byte) []byte {
	//needs to be 1600 bits long
	if len(msg) != 200 {
		panic(1337)
	}
	A := toState(msg)
	for i := 0; i < 24; i++ {
		A = chi(rhopi(theta(A)))
		A[0][0] ^= rndc[i] //iota
	}
	return fromState(A)
}

//99% sure that it works
func chi(A [5][5]uint64) [5][5]uint64 {
	var An [5][5]uint64
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			An[x][y] = A[x][y] ^ (^A[x][(y+1)%5])&A[x][(y+2)%5]
		}
	}
	return An
}

//TODO: Might not work properly
func rhopi(A [5][5]uint64) [5][5]uint64 {
	t := A[0][1]
	for i := 0; i < 24; i++ {
		j := piln[i]
		t, A[j/5][j%5] = A[j/5][j%5], bits.RotateLeft64(t, rotc[i])
	}
	return A
}

//99% sure that it works
func theta(A [5][5]uint64) [5][5]uint64 {
	var C [5]uint64
	var D [5]uint64
	for x := 0; x < 5; x++ {
		C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x]
	}
	for x := 0; x < 5; x++ {
		D[x] = C[(x+4)%5] ^ bits.RotateLeft64(C[(x+1)%5], 1)
		for y := 0; y < 5; y++ {
			A[y][x] ^= D[x]
		}
	}
	return A
}

func toState(msg []byte) [5][5]uint64 {
	var A [5][5]uint64
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			tmp := msg[8*(5*x+y)+0 : 8*(5*x+y)+8]

			A[x][y] = binary.LittleEndian.Uint64(tmp)
		}
	}
	return A
}

func fromState(A [5][5]uint64) []byte {
	S := make([]byte, 200, 200)
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			binary.LittleEndian.PutUint64(S[8*(5*x+y):8*(5*x+y)+8], A[x][y])
		}
	}
	return S
}

//---------------------

func keccak(c int, M []byte, d int, domain byte) []byte {
	return sponge(keccak160024, pad101, domain, b-c, M, d)
}

func sponge(f func(msg []byte) []byte, pad func(x, m int, domain byte) []byte, domain byte, r int, M []byte, d int) []byte {
	P := append(M, pad(r, len(M)*8, domain)...)
	n := len(P) / (r / 8)
	c := b - r
	Ps := make([]string, n, n)
	for i := 0; i < n; i++ {
		Ps[i] = string(P[i*(r/8) : (i+1)*(r/8)])
	}
	S := make([]byte, b/8, b/8)
	for i := 0; i < n; i++ {
		S = f(stringxor(S, append([]byte(Ps[i]), make([]byte, c/8, c/8)...)))
	}
	Z := make([]byte, 0)
	for {
		Z = append(Z, S[0:r/8]...)
		if d/8 <= len(Z) {
			return Z[0 : d/8]
		}
		S = f(S)
	}
}

func pad101(x, m int, domain byte) []byte {
	//we should be inserting 0110*1 but instead we will insert 0000 0110 0* 1000 0000 because we will read the bytes in little endian later
	j := mod(-m-2, x)
	result := make([]byte, (j+2)/8, (j+2)/8)
	result[0] ^= domain
	result[len(result)-1] ^= 0x80
	return result
}

func mod(m, n int) int {
	return (n + (m % n)) % n
}

func stringxor(s1 []byte, s2 ...[]byte) []byte {
	n := len(s1)
	b := make([]byte, n)
	copy(b, s1)
	for _, sn := range s2 {
		for i := 0; i < n; i++ {
			b[i] ^= sn[i]
		}
	}
	return b
}
