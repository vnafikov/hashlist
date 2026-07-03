package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	exitErrorCode = 1

	flagAlg         = "alg"
	flagExtended    = "extended"
	flagReconcile   = "reconcile"
	flagDiff        = "diff"
	flagDiffGrouped = "diff-grouped"
	flagExtract     = "extract"

	recordFieldCount         = 4
	extendedRecordFieldCount = 7

	sizeWidth = 12

	readerBufferSize = 2 * 1024 * 1024 // 2 MiB.
	writerBufferSize = 1024 * 1024     // 1 MiB.

	dateTimeLayout         = "02.01.2006 15:04:05 Z07:00"
	filenameDateTimeLayout = "2006.01.02 15-04"
)

var (
	ErrDiffFirstManifestPath = errors.New(
		"missing path: please specify the path to the first manifest as the first argument after flags",
	)
	ErrDiffSecondManifestPath = errors.New(
		"missing path: please specify the path to the second manifest as the second argument after flags",
	)
	ErrExtractMissingSourceManifestPath = errors.New(
		"missing path: please specify the path to the source manifest as the first argument after flags",
	)
	ErrMissingRootPath         = errors.New("missing path: please specify the root directory as the first argument after flags")
	ErrInvalidAlgorithm        = errors.New("invalid algorithm: must be sha256 or blake3")
	ErrInvalidFileRecordFormat = errors.New("invalid file record format")
)

type flags struct {
	alg         *string
	extended    *bool
	reconcile   *string
	diff        *bool
	diffGrouped *bool
	extract     *string
}

type config struct {
	rootPath               string
	algorithm              Algorithm
	isExtended             bool
	sourceManifestPath     string
	diffFirstManifestPath  string
	diffSecondManifestPath string
	isGrouped              bool
	extractPath            string
}

type readLine struct {
	raw    string
	record fileRecord
}

type fileRecord struct {
	hash       string
	createdAt  string
	modifiedAt string
	accessedAt string
	changedAt  string
	size       int64
	path       string
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

	if conf.diffFirstManifestPath != "" {
		manifestDiffer := NewManifestDiffer(conf.diffFirstManifestPath, conf.diffSecondManifestPath, conf.isGrouped)
		return manifestDiffer.Handle()
	}

	if conf.extractPath != "" {
		manifestExtractor := NewManifestExtractor(conf.extractPath, conf.sourceManifestPath)
		return manifestExtractor.Handle()
	}

	manifestCreator := NewManifestCreator(conf.rootPath, conf.algorithm, conf.isExtended, conf.sourceManifestPath)
	return manifestCreator.Handle()
}

func configure() (config, error) {
	f := parseFlags()
	var (
		rootPath               string
		err                    error
		algorithm              Algorithm
		sourceManifestPath     string
		diffFirstManifestPath  string
		diffSecondManifestPath string
	)
	switch {
	case *f.diff, *f.diffGrouped:
		diffFirstManifestPath, diffSecondManifestPath, err = parseDiffManifestPaths()
		if err != nil {
			return config{}, err
		}
	case *f.extract != "":
		sourceManifestPath, err = parseSourceManifestPath()
		if err != nil {
			return config{}, err
		}
	default:
		rootPath, err = parseRootPath()
		if err != nil {
			return config{}, err
		}

		algorithm, err = NewAlgorithm(*f.alg)
		if err != nil {
			return config{}, err
		}

		sourceManifestPath = *f.reconcile
	}
	return config{
		rootPath:               rootPath,
		algorithm:              algorithm,
		isExtended:             *f.extended,
		sourceManifestPath:     sourceManifestPath,
		diffFirstManifestPath:  diffFirstManifestPath,
		diffSecondManifestPath: diffSecondManifestPath,
		isGrouped:              *f.diffGrouped,
		extractPath:            *f.extract,
	}, nil
}

func parseFlags() flags {
	f := flags{
		alg: flag.String(flagAlg, "sha256", "hash algorithm: sha256, blake3"),
		extended: flag.Bool(
			flagExtended,
			true,
			"include creation, access, and change times in the order: creation, modification, access, change",
		),
		reconcile: flag.String(
			flagReconcile,
			"",
			`adds entries for new files and deletes entries for missing files,
does not recompute hashes of existing entries (relative paths, file sizes, and modification times must match exactly)`,
		),
		diff: flag.Bool(flagDiff, false, "compare two checksum manifests"),
		diffGrouped: flag.Bool(
			flagDiffGrouped,
			false,
			"compare two checksum manifests and group diff entries in the order: added, deleted, moved, modified",
		),
		extract: flag.String(flagExtract, "", "extract checksums for a path from a manifest into a new one"),
	}
	usage := flag.Usage
	flag.Usage = func() {
		_, _ = fmt.Print(`Generates a checksum manifest for a directory tree to verify file integrity.

Create a checksum manifest:
  hashlist [-alg=<algorithm>] [-extended=false] [-reconcile=<path to source manifest>] <path>

Compare checksum manifests:
  hashlist -diff[-grouped] <path to first manifest> <path to second manifest>

Extract a checksum manifest for a path:
  hashlist -extract=<path> <path to source manifest>

`)
		usage()
	}
	flag.Parse()
	return f
}

func parseDiffManifestPaths() (first, second string, err error) {
	first = flag.Arg(0)
	if first == "" {
		return "", "", ErrDiffFirstManifestPath
	}

	second = flag.Arg(1)
	if second == "" {
		return "", "", ErrDiffSecondManifestPath
	}
	return first, second, nil
}

func parseSourceManifestPath() (string, error) {
	sourceManifestPath := flag.Arg(0)
	if sourceManifestPath == "" {
		return "", ErrExtractMissingSourceManifestPath
	}
	return sourceManifestPath, nil
}

func parseRootPath() (string, error) {
	rootPath := flag.Arg(0)
	if rootPath == "" {
		return "", ErrMissingRootPath
	}
	return rootPath, nil
}

const (
	AlgorithmInvalid Algorithm = iota
	AlgorithmSHA256
	AlgorithmBLAKE3
)

type Algorithm uint8

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA256:
		return "SHA-256"
	case AlgorithmBLAKE3:
		return "BLAKE3"
	}
	return "invalid"
}

func NewAlgorithm(algorithm string) (Algorithm, error) {
	algorithm = strings.TrimSpace(algorithm)
	algorithm = strings.ToLower(algorithm)
	switch algorithm {
	case "sha256":
		return AlgorithmSHA256, nil
	case "blake3":
		return AlgorithmBLAKE3, nil
	}
	return AlgorithmInvalid, ErrInvalidAlgorithm
}

func normalizePath(path string) string {
	path = filepath.ToSlash(path)
	path = escapeTSV(path)
	return path
}

func escapeTSV(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func readNextLine(reader *bufio.Reader, manifestPath string) (line readLine, ok bool, err error) {
	line.raw, err = reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return readLine{}, false, fmt.Errorf("cannot read manifest %q: %w", manifestPath, err)
	}
	if line.raw == "" && errors.Is(err, io.EOF) {
		return readLine{}, false, nil
	}

	line.raw = trimNewLine(line.raw)
	line.record, err = parseLine(line.raw)
	if err != nil {
		return readLine{}, false, fmt.Errorf("cannot parse manifest %q: %w", manifestPath, err)
	}
	return line, true, nil
}

func trimNewLine(s string) string {
	return strings.TrimRight(s, "\r\n")
}

func parseLine(line string) (fileRecord, error) {
	parts := strings.Split(line, "\t")
	var (
		record     fileRecord
		sizeString string
	)
	switch len(parts) {
	case recordFieldCount:
		record.hash = parts[0]
		record.modifiedAt = parts[1]
		sizeString = parts[2]
		record.path = parts[3]
	case extendedRecordFieldCount:
		record.hash = parts[0]
		record.createdAt = parts[1]
		record.modifiedAt = parts[2]
		record.accessedAt = parts[3]
		record.changedAt = parts[4]
		sizeString = parts[5]
		record.path = parts[6]
	default:
		return fileRecord{}, fmt.Errorf("%w: cannot parse line: %s", ErrInvalidFileRecordFormat, line)
	}

	size, err := strconv.ParseInt(strings.TrimSpace(sizeString), 10, 64)
	if err != nil {
		return fileRecord{}, fmt.Errorf("%w: cannot parse size: %w: %s", ErrInvalidFileRecordFormat, err, line)
	}

	record.size = size
	return record, nil
}

func formatRecord(record fileRecord, isExtended bool, width int) string {
	if isExtended {
		return fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%*d\t%s",
			record.hash,
			record.createdAt,
			record.modifiedAt,
			record.accessedAt,
			record.changedAt,
			width,
			record.size,
			record.path,
		)
	}
	return fmt.Sprintf(
		"%s\t%s\t%*d\t%s",
		record.hash,
		record.modifiedAt,
		width,
		record.size,
		record.path,
	)
}
