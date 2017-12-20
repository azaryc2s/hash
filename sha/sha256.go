package sha

import (
	"encoding/binary"
	"encoding/hex"
)

const (
	chunk = 64
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

var (
	Ks = []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
)

func Sha256(msg string) string {
	return hex.EncodeToString(compute(parsing(padding([]byte(msg)))))
}

func padding(w []byte) []byte {
	var l uint64
	var k uint64
	l = uint64(len(w)) << 3 // byte * 8 = bit
	k = 448 - ((l + 1) % 512)
	if ((l + 1) % 512) > 448 {
		k += 512
	}
	result := make([]byte, 0, (l+1+k+chunk)/8)
	result = append(result[:], w...)
	//append a 1 followed by seven 0
	result = append(result, byte(128))
	n := k / 8
	result = append(result, make([]byte, n)...)
	end := make([]byte, 8, 8)
	binary.BigEndian.PutUint64(end, l)
	result = append(result, end...)
	return result
}

func parsing(pw []byte) [][]byte {
	l := len(pw) / chunk
	result := make([][]byte, l)
	for i := 0; i < l; i++ {
		result[i] = pw[i*chunk : (i+1)*chunk]
	}
	return result
}

func compute(data [][]byte) []byte {
	hashes := [8]uint32{init0, init1, init2, init3, init4, init5, init6, init7}
	for i := 1; i <= len(data); i++ {
		//Step 1. Prepare the message schedule {W_t}
		W := make([]uint32, chunk)
		for t := 0; t < chunk; t++ {
			if t <= 15 {
				W[t] = binary.BigEndian.Uint32(data[i-1][t*4 : (t+1)*4])
			} else {
				W[t] = o1(W[t-2]) + W[t-7] + o0(W[t-15]) + W[t-16]
			}
		}
		//Step 2. Initialize the eight working variables with the (i-1)th hash value
		a := hashes[0]
		b := hashes[1]
		c := hashes[2]
		d := hashes[3]
		e := hashes[4]
		f := hashes[5]
		g := hashes[6]
		h := hashes[7]

		//Step 3. for t=0 to 63
		for t := 0; t < chunk; t++ {
			T1 := h + sum1(e) + ch(e, f, g) + Ks[t] + W[t]
			T2 := sum0(a) + maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + T1
			d = c
			c = b
			b = a
			a = T1 + T2
		}

		//Step 4. Compute the i-th intermediate hash value H^i
		hashes[0] += a
		hashes[1] += b
		hashes[2] += c
		hashes[3] += d
		hashes[4] += e
		hashes[5] += f
		hashes[6] += g
		hashes[7] += h
	}
	//We now have 8 computed hashes, which we concatenate to produce the final result
	result := make([]byte, 0, 8)
	for r := 0; r < 8; r++ {
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, hashes[r])
		result = append(result, tmp...)
	}
	return result
}

func rotr(nr uint32, n uint) uint32 {
	return (nr >> n) | (nr << (32 - n))
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func sum0(x uint32) uint32 {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

func sum1(x uint32) uint32 {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

func o0(x uint32) uint32 {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

func o1(x uint32) uint32 {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}
