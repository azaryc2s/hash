package sha

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var (
	ss = []string{
		"",
		"abc",
		"uitkzz76rir",
		"ewghe64hdsrf",
		"gerzhetjudrtfz",
		"arhz7nur6tbuubc",
		"dfsghrdetgwdhf354",
		"bh7ggfdg3647358734",
		"rureujrtghz4eri56zer",
		"326478zhergesfhjt43iz5h3789g0behjzw789345ithj8gfu9",
		"0iokl2j5t90ireg78rne3hz589uzhu9in0iokl2j5t90ireg78ruiw54jt3gjio9789uew43igkj3zthjbhw637z9u4ihjne3hz589uzhu9in",
		"0iokl2j5t90ireg78ruiw54jt3gjio9789uew43igkjb8e79u34gji894u3zthjbhw637z9u4ihjne3hz589uzhu9in0iokl2j5t90ireg78ruiw54jt3gjio9789uew43igkjb8e79u34gji894u3zthjbhw637z9u4ihjne3hz589uzhu9in0iokl2j5t90ireg78ruiw54jt3gjio9789uew43igkjb8e79u34gji894u3zthjbhw637z9u4ihjne3hz589uzhu9in0iokl2j5t90ireg78ruiw54jt3gjio9789uew43igkjb8e79u34gji894u3zthjbhw637z9u4ihjne3hz589uzhu9in",
	}
)

func TestCorrectness(t *testing.T) {
	for _, s := range ss {
		if Sha256(s) != libHash([]byte(s)) {
			t.Error("Hash is wrong!")
			t.Fail()
		}
	}
}

func BenchmarkMySha256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(ss); j++ {
			Sha256(ss[j])
		}
	}
}

func BenchmarkLibSha256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(ss); j++ {
			libHash([]byte(ss[j]))
		}
	}
}

func libHash(bv []byte) string {
	hasher := sha256.New()
	hasher.Write(bv)
	return hex.EncodeToString(hasher.Sum(nil))
}
