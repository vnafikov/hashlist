package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type ManifestExtractor struct {
	extractPath        string
	sourceManifestPath string
	filename           string
	reader             *bufio.Reader
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
	sourceFile, err := me.openSourceFile()
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		if err := me.closeSourceFile(file); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(sourceFile)

	outputFile, err := me.createOutputFile()
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		if err := me.closeOutputFile(file); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(outputFile)

	return me.extract()
}

func (me *ManifestExtractor) openSourceFile() (*os.File, error) {
	if err := me.printSourceFile(); err != nil {
		return nil, err
	}

	sourceFile, err := os.Open(me.sourceManifestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open source file %q: %w", me.sourceManifestPath, err)
	}

	me.reader = bufio.NewReaderSize(sourceFile, readerBufferSize)
	return sourceFile, nil
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

func (*ManifestExtractor) closeSourceFile(sourceFile *os.File) error {
	if err := sourceFile.Close(); err != nil {
		return fmt.Errorf("cannot close source file %q: %w", sourceFile.Name(), err)
	}
	return nil
}

func (me *ManifestExtractor) createOutputFile() (*os.File, error) {
	if err := me.printOutputFile(); err != nil {
		return nil, err
	}

	outputFile, err := os.Create(me.filename)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file %q: %w", me.filename, err)
	}

	me.writer = bufio.NewWriterSize(outputFile, writerBufferSize)
	return outputFile, nil
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

func (me *ManifestExtractor) closeOutputFile(outputFile *os.File) (err error) {
	if err = me.writer.Flush(); err != nil {
		err = fmt.Errorf("cannot flush output writer: %w", err)
	}
	if e := outputFile.Close(); e != nil {
		e = fmt.Errorf("cannot close output file %q: %w", outputFile.Name(), e)
		return errors.Join(err, e)
	}
	return err
}

func (me *ManifestExtractor) extract() error {
	var extractPath string
	if me.extractPath == "." {
		extractPath = ""
	} else {
		extractPath = normalizePath(me.extractPath)
	}
	for {
		line, err := me.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("cannot read manifest %q: %w", me.sourceManifestPath, err)
		}

		if line != "" {
			path, err := me.parsePath(line)
			if err != nil {
				return err
			}

			if dirPrefix, ok := me.pathHasPrefix(path, extractPath); ok {
				line = strings.Replace(line, dirPrefix, "", 1)
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

func (*ManifestExtractor) parsePath(line string) (string, error) {
	path, ok := afterLastTab(line)
	if !ok {
		return "", fmt.Errorf("%w: cannot parse path: %s", ErrInvalidFileRecordFormat, line)
	}
	return trimNewLine(path), nil
}

func afterLastTab(line string) (string, bool) {
	i := strings.LastIndexByte(line, '\t')
	if i < 0 {
		return "", false
	}
	return line[i+1:], true
}

func (*ManifestExtractor) pathHasPrefix(path, prefix string) (dirPrefix string, ok bool) {
	if prefix == "" {
		return prefix, true
	}

	if path == prefix {
		dirPrefix = filepath.Dir(path) + "/"
		return dirPrefix, true
	}

	dirPrefix = prefix + "/"
	if strings.HasPrefix(path, dirPrefix) {
		return dirPrefix, true
	}
	return "", false
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
