package matasano

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"testing"
)

func TestProblem1(t *testing.T) {
	test := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if r := HexToBase64(test); expected != r {
		t.FailNow()
	}
}

func TestProblem2(t *testing.T) {
	s1, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.FailNow()
	}

	s2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.FailNow()
	}

	expected, err := hex.DecodeString("746865206b696420646f6e277420706c6179")
	if err != nil {
		t.FailNow()
	}

	r, err := Xor(s1, s2)
	if err != nil {
		t.FailNow()
	}

	for i := 0; i < len(s1); i++ {
		if !bytes.Equal(expected, r) {
			t.FailNow()
		}
	}
}

func TestProblem3(t *testing.T) {
	test := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	var r string
	var best_score float64

	in, err := hex.DecodeString(test)
	if err != nil {
		t.FailNow()
	}

	data, err := LoadCorpus("_testdata/aliceinwonderland.txt")
	if err != nil {
		t.FailNow()
	}

	freq := AnalyzeCorpus(data)
	for k := 0; k < 256; k++ {

		hex, err := SingleByteXor(in, byte(k))
		if err != nil {
			t.FailNow()
		}

		tmp := ScoreEnglish(string(hex), freq)
		if tmp > best_score {
			r = string(hex)
			best_score = tmp
		}
	}
	t.Logf("%s", r)
}

func TestProblem4(t *testing.T) {
	var key byte
	var plain string
	var best_score float64

	file, err := os.Open("_testdata/4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if k, p, score := DetectSingleByteXor(scanner.Text()); score > best_score {
			key = k
			plain = p
			best_score = score
			// SingleByteXor([]byte(scanner.Text()), byte(k))
		}
	}

	if plain != "Now that the party is jumping" {
		t.FailNow()
	}
	t.Logf("%s\tkey:\t%v", plain, key)
}
