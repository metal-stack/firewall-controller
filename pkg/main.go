package main

import (
	"io"
	"io/ioutil"
	"os"
)

const (
	binaryToReplace = "./main"
	newBinary       = "/home/.../bin/test"
)

func main() {
	newBin, err := os.Open(newBinary)
	if err != nil {
		panic(err)
	}
	err = replaceBinary(newBin, "")
	if err != nil {
		panic(err)
	}
}

func replaceBinary(binaryReader io.ReadCloser, checksum string) error {
	filename, err := copyToTempFile(binaryReader)
	if err != nil {
		return err
	}

	if err = os.Rename(filename, binaryToReplace); err != nil {
		return err
	}
	return nil
}

func copyToTempFile(binaryReader io.ReadCloser) (string, error) {
	file, err := ioutil.TempFile("/var/tmp", "")
	if err != nil {
		return "", err
	}

	_, err = io.Copy(file, binaryReader)
	if err != nil {
		return "", err
	}
	defer binaryReader.Close()

	err = os.Chmod(file.Name(), 0764)
	if err != nil {
		return "", err
	}
	return file.Name(), nil
}
