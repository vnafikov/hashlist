package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lukechampine.com/blake3"
)

const (
	exitErrorCode = 1

	flagAlg = "alg"

	readerBufferSize = 256 * 1024  // 256 KiB.
	writerBufferSize = 1024 * 1024 // 1 MiB.

	blake3ByteSize = 32

	dateTimeLayout         = "02.01.2006 15:04:05 Z07:00"
	filenameDateTimeLayout = "2006.01.02 15-04"
)

var (
	ErrMissingPath      = errors.New("missing path: please specify the root directory as the first argument")
	ErrInvalidAlgorithm = errors.New("invalid algorithm: must be blake3 or sha256")
)

type flags struct {
	alg *string
}

type config struct {
	rootPath  string
	algorithm Algorithm
}

type fileRecord struct {
	path       string
	size       int64
	modifiedAt string
	hash       string
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Println(err)

		os.Exit(exitErrorCode)
	}
}

func run() error {
	conf, err := configure()
	if err != nil {
		return err
	}

	manifestCreator := NewManifestCreator(conf.rootPath, conf.algorithm)
	return manifestCreator.Handle()
}

func configure() (config, error) {
	f := parseFlags()
	rootPath, err := parseRootPath()
	if err != nil {
		return config{}, err
	}

	algorithm, err := NewAlgorithm(*f.alg)
	if err != nil {
		return config{}, err
	}
	return config{
		rootPath:  rootPath,
		algorithm: algorithm,
	}, nil
}

func parseFlags() flags {
	f := flags{
		alg: flag.String(flagAlg, "blake3", "hash algorithm: blake3, sha256"),
	}
	usage := flag.Usage
	flag.Usage = func() {
		_, _ = fmt.Print(`Generates a checksum manifest for a directory tree to verify file integrity.

hashlist -alg=<algorithm> <path>

`)
		usage()
	}
	flag.Parse()
	return f
}

func parseRootPath() (string, error) {
	rootPath := flag.Arg(0)
	if rootPath == "" {
		return "", ErrMissingPath
	}
	return rootPath, nil
}

const (
	AlgorithmInvalid Algorithm = iota
	AlgorithmBLAKE3
	AlgorithmSHA256
)

type Algorithm uint8

func (a Algorithm) String() string {
	switch a {
	case AlgorithmBLAKE3:
		return "BLAKE3"
	case AlgorithmSHA256:
		return "SHA-256"
	}
	return "invalid"
}

func NewAlgorithm(algorithm string) (Algorithm, error) {
	algorithm = strings.TrimSpace(algorithm)
	algorithm = strings.ToLower(algorithm)
	switch algorithm {
	case "blake3":
		return AlgorithmBLAKE3, nil
	case "sha256":
		return AlgorithmSHA256, nil
	}
	return AlgorithmInvalid, ErrInvalidAlgorithm
}

type ManifestCreator struct {
	rootPath  string
	algorithm Algorithm
	filename  string
	buffer    []byte
	file      *os.File
	writer    *bufio.Writer
}

func (mc *ManifestCreator) Handle() error {
	log.Printf(
		`Creating hash list for:
	%s

`,
		mc.rootPath,
	)

	if err := mc.createFile(); err != nil {
		return err
	}
	defer func() {
		if err := mc.closeFile(); err != nil {
			log.Printf("ERROR: cannot close output file: %s.", err)
		}
	}()

	return filepath.WalkDir(mc.rootPath, mc.handleEntry)
}

func (mc *ManifestCreator) createFile() error {
	absolutePath, err := filepath.Abs(mc.filename)
	if err != nil {
		return err
	}

	log.Printf("Creating hash list in %q.", absolutePath)

	mc.file, err = os.Create(mc.filename)
	if err != nil {
		return err
	}

	mc.writer = bufio.NewWriterSize(mc.file, writerBufferSize)
	return nil
}

func (mc *ManifestCreator) closeFile() error {
	if err := mc.writer.Flush(); err != nil {
		return err
	}

	if err := mc.file.Close(); err != nil {
		return err
	}

	absolutePath, err := filepath.Abs(mc.file.Name())
	if err != nil {
		return err
	}

	log.Printf("Hash list created in %q.", absolutePath)

	return nil
}

func (mc *ManifestCreator) handleEntry(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		log.Printf("ERROR: cannot read directory entry %q: %s.", path, err)

		return nil
	}
	if entry.IsDir() {
		return nil
	}
	if !entry.Type().IsRegular() {
		return nil
	}
	return mc.handleFileEntry(path)
}

func (mc *ManifestCreator) handleFileEntry(path string) error {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: cannot read file %q: %s.", path, err)

		return nil
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("ERROR: cannot close file %q: %s.", path, err)
		}
	}()

	info, err := file.Stat()
	if err != nil {
		log.Printf("ERROR: cannot read file info %q: %s.", path, err)

		return nil
	}

	record, err := mc.readFileRecord(path, file, info)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(mc.writer, "%s\t%d\t%s\t%s\n", escapeTSV(record.path), record.size, record.modifiedAt, record.hash)
	return err
}

func (mc *ManifestCreator) readFileRecord(path string, file *os.File, info fs.FileInfo) (fileRecord, error) {
	h, err := mc.hashFile(file)
	if err != nil {
		return fileRecord{}, err
	}

	record := fileRecord{
		size:       info.Size(),
		modifiedAt: info.ModTime().Format(dateTimeLayout),
		hash:       h,
	}
	if record.path, err = filepath.Rel(mc.rootPath, path); err != nil {
		record.path = path
	}
	return record, nil
}

func (mc *ManifestCreator) hashFile(file *os.File) (string, error) {
	var h hash.Hash
	switch mc.algorithm {
	case AlgorithmBLAKE3:
		h = blake3.New(blake3ByteSize, nil)
	case AlgorithmSHA256:
		h = sha256.New()
	default:
		return "", ErrInvalidAlgorithm
	}

	if _, err := io.CopyBuffer(h, file, mc.buffer); err != nil {
		return "", err
	}

	sum := h.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func escapeTSV(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func NewManifestCreator(rootPath string, algorithm Algorithm) ManifestCreator {
	rootPath = filepath.Clean(rootPath)
	return ManifestCreator{
		rootPath:  rootPath,
		algorithm: algorithm,
		filename:  filename(rootPath, algorithm),
		buffer:    make([]byte, readerBufferSize),
	}
}

func filename(rootPath string, algorithm Algorithm) string {
	createdAt := time.Now().Format(filenameDateTimeLayout)
	base := filepath.Base(rootPath)
	if base == string(os.PathSeparator) {
		base = "root"
	}
	return fmt.Sprintf("%s - %s (%s).tsv", createdAt, base, algorithm)
}
