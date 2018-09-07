package matasano

import (
	"errors"
	"fmt"
)

func PadPKCS7(in []byte, size int) ([]byte, error) {

	if len(in) > size {
		return nil, errors.New(fmt.Sprintf("Size %d is lower than input length %d", size, len(in)))
	}

	if len(in) == size {
		return in, nil
	}

	pad := size - len(in)

	for i := 0; i < pad; i++ {
		in = append(in, byte(pad))
	}

	return in, nil
}
