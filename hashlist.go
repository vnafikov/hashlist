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

	flagAlg     = "alg"
	flagExtract = "extract"

	readerBufferSize          = 256 * 1024      // 256 KiB.
	writerBufferSize          = 1024 * 1024     // 1 MiB.
	extractorReaderBufferSize = 2 * 1024 * 1024 // 2 MiB.

	printedPathLen = 70
	cleanLine      = "\r                                                                              \r"

	blake3ByteSize = 32

	dateTimeLayout         = "02.01.2006 15:04:05 Z07:00"
	filenameDateTimeLayout = "2006.01.02 15-04"
)

var (
	ErrMissingRootPath           = errors.New("missing path: please specify the root directory as the first argument after flags")
	ErrMissingSourceManifestPath = errors.New(
		"missing path: please specify the path to the source manifest as the first argument after flags",
	)
	ErrInvalidAlgorithm        = errors.New("invalid algorithm: must be sha256 or blake3")
	ErrInvalidFileRecordFormat = errors.New("invalid file record format")
)

type flags struct {
	alg     *string
	extract *string
}

type config struct {
	rootPath  string
	algorithm Algorithm

	extractPath        string
	sourceManifestPath string
}

type fileRecord struct {
	hash       string
	modifiedAt string
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

	if conf.extractPath != "" {
		manifestExtractor := NewManifestExtractor(conf.extractPath, conf.sourceManifestPath)
		return manifestExtractor.Handle()
	}

	manifestCreator := NewManifestCreator(conf.rootPath, conf.algorithm)
	return manifestCreator.Handle()
}

func configure() (config, error) {
	f := parseFlags()
	var (
		rootPath           string
		err                error
		algorithm          Algorithm
		sourceManifestPath string
	)
	if *f.extract == "" {
		rootPath, err = parseRootPath()
		if err != nil {
			return config{}, err
		}

		algorithm, err = NewAlgorithm(*f.alg)
		if err != nil {
			return config{}, err
		}
	} else {
		sourceManifestPath, err = parseSourceManifestPath()
		if err != nil {
			return config{}, err
		}
	}
	return config{
		rootPath:           rootPath,
		algorithm:          algorithm,
		extractPath:        *f.extract,
		sourceManifestPath: sourceManifestPath,
	}, nil
}

func parseFlags() flags {
	f := flags{
		alg:     flag.String(flagAlg, "sha256", "hash algorithm: sha256, blake3"),
		extract: flag.String(flagExtract, "", "extract checksums for a path from a manifest into a new one"),
	}
	usage := flag.Usage
	flag.Usage = func() {
		_, _ = fmt.Print(`Generates a checksum manifest for a directory tree to verify file integrity.

Create a checksum manifest:
  hashlist -alg=<algorithm> <path>

Extract a checksum manifest for a path:
  hashlist -extract=<path> <path to source manifest>

`)
		usage()
	}
	flag.Parse()
	return f
}

func parseRootPath() (string, error) {
	rootPath := flag.Arg(0)
	if rootPath == "" {
		return "", ErrMissingRootPath
	}
	return rootPath, nil
}

func parseSourceManifestPath() (string, error) {
	sourceManifestPath := flag.Arg(0)
	if sourceManifestPath == "" {
		return "", ErrMissingSourceManifestPath
	}
	return sourceManifestPath, nil
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

type ManifestCreator struct {
	rootPath  string
	algorithm Algorithm
	filename  string
	buffer    []byte
	file      *os.File
	writer    *bufio.Writer
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
	if err := mc.createFile(); err != nil {
		return err
	}
	defer func() {
		if err := mc.closeFile(); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}()

	return filepath.WalkDir(mc.rootPath, mc.handleEntry)
}

func (mc *ManifestCreator) createFile() error {
	err := mc.printFile()
	if err != nil {
		return err
	}

	mc.file, err = os.Create(mc.filename)
	if err != nil {
		return fmt.Errorf("cannot create output file %q: %w", mc.filename, err)
	}

	mc.writer = bufio.NewWriterSize(mc.file, writerBufferSize)
	return nil
}

func (mc *ManifestCreator) printFile() error {
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

func (mc *ManifestCreator) closeFile() error {
	if err := mc.writer.Flush(); err != nil {
		return fmt.Errorf("cannot flush output writer: %w", err)
	}

	if err := mc.file.Close(); err != nil {
		return fmt.Errorf("cannot close output file %q: %w", mc.file.Name(), err)
	}
	return nil
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
	return mc.handleFileEntry(path)
}

func (*ManifestCreator) printPath(path string) {
	r := []rune(path)
	l := len(r)
	if l > printedPathLen {
		path = "…" + string(r[l-printedPathLen:])
	}
	_, _ = fmt.Print(cleanLine + path)
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
		log.Printf("ERROR: cannot read file info for %q: %s.", path, err)

		return nil
	}

	record, err := mc.readFileRecord(path, file, info)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(mc.writer, "%s\t%s\t%12d\t%s\n", record.hash, record.modifiedAt, record.size, escapeTSV(record.path))
	return err
}

func (mc *ManifestCreator) readFileRecord(path string, file *os.File, info fs.FileInfo) (fileRecord, error) {
	h, err := mc.hashFile(file)
	if err != nil {
		return fileRecord{}, err
	}

	record := fileRecord{
		hash:       h,
		modifiedAt: info.ModTime().Format(dateTimeLayout),
		size:       info.Size(),
	}
	if record.path, err = filepath.Rel(mc.rootPath, path); err != nil {
		record.path = path
	}
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

func escapeTSV(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func (*ManifestCreator) printDone() {
	_, _ = fmt.Print(cleanLine)
	log.Println("Hash list created!")
}

func NewManifestCreator(rootPath string, algorithm Algorithm) ManifestCreator {
	rootPath = filepath.Clean(rootPath)
	return ManifestCreator{
		rootPath:  rootPath,
		algorithm: algorithm,
		filename:  filenameForCreate(rootPath, algorithm),
		buffer:    make([]byte, readerBufferSize),
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

type ManifestExtractor struct {
	extractPath        string
	sourceManifestPath string
	filename           string
	buffer             []byte
	sourceFile         *os.File
	outputFile         *os.File
	writer             *bufio.Writer
}

func (me *ManifestExtractor) Handle() error {
	me.printStart()

	if err := me.handle(); err != nil {
		return err
	}

	me.printDone()

	return nil
}

func (me *ManifestExtractor) printStart() {
	log.Printf(
		`Extracting hash list for:
	%s

`,
		me.extractPath,
	)
}

func (me *ManifestExtractor) handle() error {
	if err := me.openSourceFile(); err != nil {
		return err
	}
	defer func() {
		if err := me.closeSourceFile(); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}()

	if err := me.createOutputFile(); err != nil {
		return err
	}
	defer func() {
		if err := me.closeOutputFile(); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}()

	return me.extract()
}

func (me *ManifestExtractor) openSourceFile() error {
	err := me.printSourceFile()
	if err != nil {
		return err
	}

	me.sourceFile, err = os.Open(me.sourceManifestPath)
	if err != nil {
		return fmt.Errorf("cannot open source file %q: %w", me.sourceManifestPath, err)
	}
	return nil
}

func (me *ManifestExtractor) printSourceFile() error {
	absolutePath, err := filepath.Abs(me.sourceManifestPath)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", me.sourceManifestPath, err)
	}

	log.Printf(
		`From:
	%s

`,
		absolutePath,
	)
	return nil
}

func (me *ManifestExtractor) closeSourceFile() error {
	if err := me.sourceFile.Close(); err != nil {
		return fmt.Errorf("cannot close source file %q: %w", me.sourceFile.Name(), err)
	}
	return nil
}

func (me *ManifestExtractor) createOutputFile() error {
	err := me.printOutputFile()
	if err != nil {
		return err
	}

	me.outputFile, err = os.Create(me.filename)
	if err != nil {
		return fmt.Errorf("cannot create output file %q: %w", me.filename, err)
	}

	me.writer = bufio.NewWriterSize(me.outputFile, writerBufferSize)
	return nil
}

func (me *ManifestExtractor) printOutputFile() error {
	absolutePath, err := filepath.Abs(me.filename)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", me.filename, err)
	}

	log.Printf(
		`Writing to:
	%s

`,
		absolutePath,
	)
	return nil
}

func (me *ManifestExtractor) closeOutputFile() error {
	if err := me.writer.Flush(); err != nil {
		return fmt.Errorf("cannot flush output writer: %w", err)
	}

	if err := me.outputFile.Close(); err != nil {
		return fmt.Errorf("cannot close output file %q: %w", me.outputFile.Name(), err)
	}
	return nil
}

func (me *ManifestExtractor) extract() error {
	var extractPath string
	if me.extractPath == "." {
		extractPath = ""
	} else {
		extractPath = me.extractPath
	}
	reader := bufio.NewReaderSize(me.sourceFile, extractorReaderBufferSize)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("cannot read manifest %q: %w", me.sourceFile.Name(), err)
		}

		if line != "" {
			path, err := me.parsePath(line)
			if err != nil {
				return err
			}

			if me.pathHasPrefix(path, extractPath) {
				if _, err := fmt.Fprint(me.writer, line); err != nil {
					return err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return nil
}

func (me *ManifestExtractor) parsePath(line string) (string, error) {
	path, ok := me.afterThirdTab(line)
	if !ok {
		return "", ErrInvalidFileRecordFormat
	}

	path = strings.TrimSpace(path)
	return path, nil
}

func (*ManifestExtractor) afterThirdTab(line string) (string, bool) {
	i := -1
	for n := 0; n < 3; n++ {
		j := strings.IndexByte(line[i+1:], '\t')
		if j < 0 {
			return "", false
		}

		i += j + 1
	}
	return line[i+1:], true
}

func (*ManifestExtractor) pathHasPrefix(path, prefix string) bool {
	if prefix == "" || path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+string(os.PathSeparator))
}

func (*ManifestExtractor) printDone() {
	log.Println("Hash list extracted!")
}

func NewManifestExtractor(extractPath, sourceManifestPath string) ManifestExtractor {
	extractPath = filepath.Clean(extractPath)
	sourceManifestPath = filepath.Clean(sourceManifestPath)
	return ManifestExtractor{
		extractPath:        extractPath,
		sourceManifestPath: sourceManifestPath,
		filename:           filenameForExtract(extractPath, sourceManifestPath),
		buffer:             make([]byte, readerBufferSize),
	}
}

func filenameForExtract(extractPath, sourceManifestPath string) string {
	extractBase := filepath.Base(extractPath)
	if extractBase == string(os.PathSeparator) {
		extractBase = "root"
	} else {
		extractBase = strings.ReplaceAll(extractBase, ":", "")
	}
	sourceManifestBase := filepath.Base(sourceManifestPath)
	sourceManifestExt := filepath.Ext(sourceManifestBase)
	sourceManifestName := strings.TrimSuffix(sourceManifestBase, sourceManifestExt)
	return fmt.Sprintf("%s - %s%s", sourceManifestName, extractBase, sourceManifestExt)
}
