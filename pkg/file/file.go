package file

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
)

func Equal(source, target string) bool {
	sourceChecksum, err := Checksum(source)
	if err != nil {
		return false
	}

	targetChecksum, err := Checksum(target)
	if err != nil {
		return false
	}

	return bytes.Equal(sourceChecksum, targetChecksum)
}

func Checksum(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
