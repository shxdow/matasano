package matasano

import (
	"bytes"
	"encoding/base64"
	"testing"
	"unicode/utf8"
)

func TestPadLenPKCS7(t *testing.T) {
	in := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	expected := 4
	block_size := 20

	if got, err := PadLenPKCS7(in, block_size); got != expected && err != nil {
		t.Logf("want: %+v, got: %+v", expected, got)
		t.FailNow()
	}

}

func TestProblem9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	size := 20

	out := PadPKCS7(in, size)
	l, err := PadLenPKCS7(in, size)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if !bytes.Equal(out[:len(out)-l], expected) {
		t.Logf("got: %v; want: %v", out[:len(out)-l], expected)
		t.FailNow()
	} else {
		t.Logf("%+v", out[:len(out)-l])
		t.Logf("%+v", expected)
	}
}

func TestAESECB(t *testing.T) {

	test := []byte("Hello world")
	key := []byte("YELLOW SUBMARINE")

	// Encrypt the test string
	enc, err := AESEncryptECB(test, key)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Decrypt the test string
	plain, err := AESDecryptECB(enc, key)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if !bytes.Equal(plain[:len(test)], test) {
		t.Logf("got: %s; want: %s", plain[:len(test)], test)
		t.FailNow()
	}
}

func TestAESCBC(t *testing.T) {

	test := []byte("Hello world, I've coded quite alot lately...")
	key := []byte("YELLOW SUBMARINE")
	block_size := 16
	iv := make([]byte, block_size)

	// Encrypt the test string
	enc, err := AESEncryptCBC(test, key, iv)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Decrypt the test string
	plain, err := AESDecryptCBC(enc, key, iv)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if !bytes.Equal(plain[:len(test)], test) {
		t.Logf("got: %s; want: %s", plain[:len(test)], test)
		t.FailNow()
	}
}

func TestProblem10(t *testing.T) {

	var filename string = "_testdata/10.txt"
	var key []byte = []byte("YELLOW SUBMARINE")
	var block_size = 16
	var iv []byte = make([]byte, block_size)
	var s string

	b64, err := LoadCorpus(filename)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	data, err := base64.StdEncoding.DecodeString(b64)

	enc, err := AESDecryptCBC(data, key, iv)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	for len(enc) > 0 {
		r, size := utf8.DecodeRune(enc)
		s += string(r)
		enc = enc[size:]
	}

	t.Logf("%s", s)
}

func TestAESGenerateKey(t *testing.T) {
	if _, err := AESGenerateKey(16); err != nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestProblem11(t *testing.T) {
	in := "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
	size := 16

	enc, err, want := AESEncryptionOracle([]byte(in))
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	got, err := AESDetectionOracle(enc, len(PadPKCS7([]byte(in), size)))
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if got != want {
		t.Logf("got: %s, want: %s", got, want)
		t.FailNow()
	}

	t.Logf("encryption mode detected: %s", got)
}
