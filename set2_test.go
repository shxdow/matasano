package matasano

import (
	"bytes"
	"testing"
)

func TestProblem9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	size := 20

	if out, err := PadPKCS7(in, size); !bytes.Equal(out, expected) || err != nil {
		t.Log(err)
		t.FailNow()
	} else {
		t.Logf("%+v", string(out))
		t.Logf("%+v", out)
	}
}

func TestAES(t *testing.T) {

	data := []byte("Hello world")
	key := []byte("YELLOW SUBMARINE")

	// Encrypt the test string
	enc, err := AESEncryptECB(data, key)
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

	if !bytes.Equal(plain, enc) {
		t.Logf("%+v", plain)
		t.Logf("%+v", enc)
		t.FailNow()
	}
}
