package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	exitErrorCode = 1

	flagAlg = "alg"
)

const (
	AlgorithmInvalid Algorithm = iota
	AlgorithmBLAKE3
	AlgorithmSHA256
)

var (
	ErrMissingPath      = errors.New("missing path: please specify the root directory as the first argument")
	ErrInvalidAlgorithm = errors.New("invalid algorithm: must be blake3 or sha256")

	rootPath  string
	algorithm Algorithm
)

type Algorithm uint8

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(exitErrorCode)
	}
}

func run() error {
	if err := setupFlags(); err != nil {
		return err
	}
	return nil
}

func setupFlags() error {
	algFlag := flag.String(flagAlg, "blake3", "hash algorithm: blake3, sha256")

	usage := flag.Usage
	flag.Usage = func() {
		_, _ = fmt.Print(`Generates a checksum manifest for a directory tree to verify file integrity.

hashlist <path> -alg <algorithm>

`)
		usage()
	}

	flag.Parse()
	if err := setPath(); err != nil {
		return err
	}
	return setAlgorithm(*algFlag)
}

func setPath() error {
	rootPath = flag.Arg(0)
	if rootPath == "" {
		return ErrMissingPath
	}
	return nil
}

func setAlgorithm(alg string) error {
	alg = strings.TrimSpace(alg)
	alg = strings.ToLower(alg)
	switch alg {
	case "blake3":
		algorithm = AlgorithmBLAKE3
		return nil
	case "sha256":
		algorithm = AlgorithmSHA256
		return nil
	}
	return ErrInvalidAlgorithm
}
