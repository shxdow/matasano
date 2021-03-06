package matasano

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
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
		t.Log(err)
		t.FailNow()
	}

	s2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	expected, err := hex.DecodeString("746865206b696420646f6e277420706c6179")
	if err != nil {
		t.FailNow()
	}

	r, err := Xor(s1, s2)
	if err != nil {
		t.Log(err)
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
		t.Log(err)
		t.FailNow()
	}

	data, err := LoadCorpus("_testdata/aliceinwonderland.txt")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	freq := AnalyzeCorpus(data)
	for k := 0; k < 256; k++ {

		hex, err := SingleByteXor(in, byte(k))
		if err != nil {
			t.Log(err)
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
		t.Log(err)
		log.Fatal(err)
	}
	defer file.Close()

	_, freq := initCorpus()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if k, p, score := DetectSingleByteXor(scanner.Text(), freq); score > best_score {
			key = k
			plain = p
			best_score = score
		}
	}

	if plain != "Now that the party is jumping\n" {
		t.FailNow()
	}
	t.Logf("%s\tkey:\t%v", plain, key)
}

func TestProblem5(t *testing.T) {

	in := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	test := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	if enc := RepeatingKeyXor([]byte(in), []byte("ICE")); fmt.Sprintf("%x", string(enc)) != test {
		t.Logf("%s", test)
		t.Logf("len:%d", len(test))
		t.Logf("%x", fmt.Sprintf("%s", enc))
		t.Logf("len: %d", len(fmt.Sprintf("%s", enc)))
		t.FailNow()
	}
	// else {
	// t.Logf("%x", string(RepeatingKeyXor([]byte("Alpha"), []byte("HEY"))))
	// }
}

func TestHammingDistance(t *testing.T) {
	if d := ComputeHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")); d != 37 {
		t.Logf("distance: %d", d)
		t.FailNow()
	}
}

func TestTransposeBlocks(t *testing.T) {
	matrix := [][]byte{
		[]byte{'a', 'b', 'c'},
		[]byte{'d', 'e', 'f'},
	}
	test := [][]byte{
		[]byte{'a', 'd'},
		[]byte{'b', 'e'},
		[]byte{'c', 'f'},
	}

	if out := TransposeBlocks(matrix); !reflect.DeepEqual(test, out) {
		t.Logf("in: %+v", matrix)
		t.Logf("out: %+v", out)
		t.Logf("test: %+v", test)
		t.FailNow()
	}
}

func TestSplit(t *testing.T) {
	size := 3
	stream := []byte{'a', 'b', 'c', 'd', 'e', 'f', 'g'}
	test := [][]byte{
		[]byte{'a', 'b', 'c'},
		[]byte{'d', 'e', 'f'},
		[]byte{'g'},
	}

	if out := Split(stream, size); !reflect.DeepEqual(test, out) {
		t.FailNow()
	}
}

func TestProblem6(t *testing.T) {

	filename := "_testdata/6.txt"

	b64, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log(err)
		log.Fatal("Error opening file")
	}

	enc, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		t.Log(err)
		log.Fatal(err)
	}

	key, plain := BreakRepeatingKeyXor(enc)

	t.Logf("\nkey: %s\ndata: %s", key, plain)
}

func TestProblem7(t *testing.T) {

	filename := "_testdata/7.txt"
	key := []byte("YELLOW SUBMARINE")

	b64, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	enc, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	s, err := AESDecryptECB([]byte(enc), key)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	t.Logf("plaintext: %s", s)
}

func TestProblem8(t *testing.T) {
	var best_freq int
	var e string
	test := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

	file, err := os.Open("_testdata/8.txt")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if freq := DetectAESECB(scanner.Text()); freq > best_freq {
			e = scanner.Text()
			best_freq = freq
		}
	}

	if e != test {
		t.FailNow()
	}

	t.Logf("ECB encrypted data: %s", e)
}
