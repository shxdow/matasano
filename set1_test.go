package matasano

import (
	"encoding/hex"
	"testing"
)

func TestProblem1(t *testing.T) {
	test := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if r := HexToBase64(test); expected != r {
		t.Failed()
	}
}

func TestProblem2(t *testing.T) {
	s1 := []byte("1c0111001f010100061a024b53535009181c")
	s2 := []byte("686974207468652062756c6c277320657965")
	expected := "746865206b696420646f6e277420706c6179"

	r, err := Xor(s1, s2)
	if err != nil {
		t.Failed()
	}

	for i := 0; i < len(s1); i++ {
		if expected[i] != r[i] || err != nil {
			t.Failed()
		}
	}
}

func TestProblem3(t *testing.T) {
	test := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	var r string
	var best_score float64

	in, err := hex.DecodeString(test)
	if err != nil {
		t.Failed()
	}

	data, err := LoadCorpus("_testdata/aliceinwonderland.txt")
	if err != nil {
		t.Failed()
	}

	freq := AnalyzeCorpus(data)
	for k := 0; k < 256; k++ {

		hex, err := SingleByteXor(in, byte(k))
		if err != nil {
			t.Failed()
		}

		tmp := ScoreEnglish(string(hex), freq)
		if tmp > best_score {
			r = string(hex)
			best_score = tmp
		}
	}
	t.Logf("%s", r)
}
