package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	"github.com/vnafikov/hashlist/filesystem"
)

const (
	fileBufferSize = 256 * 1024 // 256 KiB.

	printedPathLen = 70
	cleanLine      = "\r                                                                              \r"

	blake3ByteSize = 32
)

type ManifestCreator struct {
	rootPath           string
	algorithm          Algorithm
	isExtended         bool
	sourceManifestPath string
	filename           string
	buffer             []byte
	reader             *bufio.Reader
	readLine           readLine
	isReadDone         bool
	writer             *bufio.Writer
}

func (mc *ManifestCreator) Handle() error {
	mc.printStart()

	if err := mc.handle(); err != nil {
		return err
	}

	mc.printDone()

	return nil
}

func (mc *ManifestCreator) printStart() {
	log.Printf(
		`Creating %s hash list for:
	%s

`,
		mc.algorithm,
		mc.rootPath,
	)
}

func (mc *ManifestCreator) handle() error {
	if mc.sourceManifestPath != "" {
		sourceFile, err := mc.openSourceFile()
		if err != nil {
			return err
		}
		defer func(file *os.File) {
			if err := mc.closeSourceFile(file); err != nil {
				log.Printf("ERROR: %s.", err)
			}
		}(sourceFile)
	}

	outputFile, err := mc.createOutputFile()
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		if err := mc.closeOutputFile(file); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(outputFile)

	return filepath.WalkDir(mc.rootPath, mc.handleEntry)
}

func (mc *ManifestCreator) openSourceFile() (*os.File, error) {
	if err := mc.printSourceFile(); err != nil {
		return nil, err
	}

	sourceFile, err := os.Open(mc.sourceManifestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open source file %q: %w", mc.sourceManifestPath, err)
	}

	mc.reader = bufio.NewReaderSize(sourceFile, readerBufferSize)
	return sourceFile, nil
}

func (mc *ManifestCreator) printSourceFile() error {
	absolutePath, err := filepath.Abs(mc.sourceManifestPath)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", mc.sourceManifestPath, err)
	}

	log.Printf(
		`Source manifest:
	%s

`,
		absolutePath,
	)
	return nil
}

func (*ManifestCreator) closeSourceFile(sourceFile *os.File) error {
	if err := sourceFile.Close(); err != nil {
		return fmt.Errorf("cannot close source file %q: %w", sourceFile.Name(), err)
	}
	return nil
}

func (mc *ManifestCreator) createOutputFile() (*os.File, error) {
	if err := mc.printOutputFile(); err != nil {
		return nil, err
	}

	outputFile, err := os.Create(mc.filename)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file %q: %w", mc.filename, err)
	}

	mc.writer = bufio.NewWriterSize(outputFile, writerBufferSize)
	return outputFile, nil
}

func (mc *ManifestCreator) printOutputFile() error {
	absolutePath, err := filepath.Abs(mc.filename)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", mc.filename, err)
	}

	log.Printf(
		`Writing to:
	%s

`,
		absolutePath,
	)
	return nil
}

func (mc *ManifestCreator) closeOutputFile(outputFile *os.File) (err error) {
	if err = mc.writer.Flush(); err != nil {
		err = fmt.Errorf("cannot flush output writer: %w", err)
	}
	if e := outputFile.Close(); e != nil {
		e = fmt.Errorf("cannot close output file %q: %w", outputFile.Name(), e)
		return errors.Join(err, e)
	}
	return err
}

func (mc *ManifestCreator) handleEntry(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		log.Printf("ERROR: cannot read directory entry %q: %s.", path, err)

		return nil
	}
	if entry.IsDir() {
		mc.printPath(path)

		return nil
	}
	if !entry.Type().IsRegular() {
		return nil
	}
	return mc.handleFileEntry(path, entry)
}

func (*ManifestCreator) printPath(path string) {
	r := []rune(path)
	l := len(r)
	if l > printedPathLen {
		path = "…" + string(r[l-printedPathLen:])
	}
	_, _ = fmt.Print(cleanLine + path)
}

func (mc *ManifestCreator) handleFileEntry(path string, entry fs.DirEntry) error {
	info, err := entry.Info()
	if err != nil {
		log.Printf("ERROR: cannot read file info for %q: %s.", path, err)

		return nil
	}

	relPath := mc.relativePath(path)
	normalizedPath := normalizePath(relPath)
	if mc.reader != nil {
		found, err := mc.handleSourceManifest(info, path, normalizedPath)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}

	record, err := mc.readFileRecordWithHash(info, path, normalizedPath)
	if err != nil {
		return err
	}
	return mc.writeLine(record)
}

func (mc *ManifestCreator) relativePath(path string) string {
	if path == mc.rootPath {
		return filepath.Base(path)
	}

	relPath, err := filepath.Rel(mc.rootPath, path)
	if err != nil {
		return path
	}
	return relPath
}

func (mc *ManifestCreator) handleSourceManifest(info fs.FileInfo, path, normalizedPath string) (found bool, err error) {
	for !mc.isReadDone && mc.readLine.record.path < normalizedPath {
		if err := mc.readNextLine(); err != nil {
			return false, err
		}
	}
	if mc.readLine.record.path == normalizedPath &&
		mc.readLine.record.size == info.Size() &&
		mc.readLine.record.modifiedAt == mc.formattedTime(info.ModTime()) {
		record, err := mc.readFileRecord(info, path, normalizedPath)
		if err != nil {
			return false, err
		}

		record.hash = mc.readLine.record.hash
		if err := mc.writeLine(record); err != nil {
			return false, err
		}

		if mc.isReadDone {
			mc.readLine.record = fileRecord{}
			return true, nil
		}

		if err := mc.readNextLine(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (mc *ManifestCreator) readNextLine() error {
	var (
		ok  bool
		err error
	)
	mc.readLine, ok, err = readNextLine(mc.reader, mc.sourceManifestPath)
	if err != nil {
		return err
	}

	if !ok {
		mc.isReadDone = true
	}
	return nil
}

func (*ManifestCreator) formattedTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(dateTimeLayout)
}

func (mc *ManifestCreator) readFileRecord(info fs.FileInfo, path, normalizedPath string) (fileRecord, error) {
	record := fileRecord{
		modifiedAt: mc.formattedTime(info.ModTime()),
		size:       info.Size(),
		path:       normalizedPath,
	}
	if mc.isExtended {
		times, err := filesystem.NewTimes(info, path)
		if err != nil {
			return fileRecord{}, err
		}

		record.createdAt = mc.formattedTime(times.Creation)
		record.accessedAt = mc.formattedTime(times.Access)
		record.changedAt = mc.formattedTime(times.Change)
	}
	return record, nil
}

func (mc *ManifestCreator) writeLine(record fileRecord) error {
	line := formatRecord(record, mc.isExtended, sizeWidth)
	_, err := fmt.Fprintln(mc.writer, line)
	return err
}

func (mc *ManifestCreator) readFileRecordWithHash(info fs.FileInfo, path, normalizedPath string) (fileRecord, error) {
	mc.printPath(path + " (hashing)")

	record, err := mc.readFileRecord(info, path, normalizedPath)
	if err != nil {
		return fileRecord{}, err
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: cannot read file %q: %s.", path, err)

		return fileRecord{}, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("ERROR: cannot close file %q: %s.", path, err)
		}
	}()

	h, err := mc.hashFile(file)
	if err != nil {
		return fileRecord{}, err
	}

	record.hash = h
	return record, nil
}

func (mc *ManifestCreator) hashFile(file *os.File) (string, error) {
	var h hash.Hash
	switch mc.algorithm {
	case AlgorithmSHA256:
		h = sha256.New()
	case AlgorithmBLAKE3:
		h = blake3.New(blake3ByteSize, nil)
	default:
		return "", ErrInvalidAlgorithm
	}

	if _, err := io.CopyBuffer(h, file, mc.buffer); err != nil {
		return "", err
	}

	sum := h.Sum(nil)
	hexSum := hex.EncodeToString(sum)
	return hexSum, nil
}

func (*ManifestCreator) printDone() {
	_, _ = fmt.Print(cleanLine)
	log.Println("Hash list created!")
}

func NewManifestCreator(rootPath string, algorithm Algorithm, isExtended bool, sourceManifestPath string) ManifestCreator {
	rootPath = filepath.Clean(rootPath)
	return ManifestCreator{
		rootPath:           rootPath,
		algorithm:          algorithm,
		isExtended:         isExtended,
		sourceManifestPath: sourceManifestPath,
		filename:           filenameForCreate(rootPath, algorithm),
		buffer:             make([]byte, fileBufferSize),
	}
}

func filenameForCreate(rootPath string, algorithm Algorithm) string {
	createdAt := time.Now().Format(filenameDateTimeLayout)
	base := filepath.Base(rootPath)
	if base == string(os.PathSeparator) {
		base = "root"
	} else {
		base = strings.ReplaceAll(base, ":", "")
	}
	return fmt.Sprintf("%s - %s (%s).tsv", createdAt, base, algorithm)
}
