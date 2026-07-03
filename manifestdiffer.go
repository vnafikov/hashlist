package main

import (
	"bufio"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	ansiReset                = "\x1b[0m"
	ansiSoftRedBackground    = "\x1b[38;5;52;48;5;224m"
	ansiSoftGreenBackground  = "\x1b[38;5;22;48;5;194m"
	ansiSoftPurpleBackground = "\x1b[38;5;55;48;5;183m"
	ansiGray                 = "\x1b[38;5;242m"

	markAdded    = "+"
	markDeleted  = "-"
	markMoved    = "→"
	markModified = "±"
)

const (
	diffTypeInvalid diffType = iota
	diffTypeAdded
	diffTypeDeleted
	diffTypeMoved
	diffTypeModified
)

type diffType uint8

type ManifestDiffer struct {
	firstManifestPath  string
	secondManifestPath string
	isGrouped          bool
	filename           string
	firstReader        *bufio.Reader
	firstHash          hash.Hash
	secondReader       *bufio.Reader
	secondHash         hash.Hash
	writer             *bufio.Writer
}

type diffLine struct {
	readLine
	isExtended bool
}

type diffResult struct {
	diffType diffType
	first    diffLine
	second   diffLine
}

func (md *ManifestDiffer) Handle() error {
	md.printStart()

	if err := md.handle(); err != nil {
		return err
	}

	md.printDone()

	return nil
}

func (*ManifestDiffer) printStart() {
	log.Println("Comparing hash lists.")
}

func (md *ManifestDiffer) handle() error {
	if err := md.printFiles(); err != nil {
		return err
	}

	firstFile, err := md.openFirstFile()
	if err != nil {
		return err
	}
	defer func(firstFile *os.File) {
		if err := md.closeFile(firstFile); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(firstFile)

	secondFile, err := md.openSecondFile()
	if err != nil {
		return err
	}
	defer func(secondFile *os.File) {
		if err := md.closeFile(secondFile); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(secondFile)

	outputFile, err := md.createOutputFile()
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		if err := md.closeOutputFile(file); err != nil {
			log.Printf("ERROR: %s.", err)
		}
	}(outputFile)

	return md.compare()
}

func (md *ManifestDiffer) printFiles() error {
	firstAbsolutePath, err := filepath.Abs(md.firstManifestPath)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", md.firstManifestPath, err)
	}

	secondAbsolutePath, err := filepath.Abs(md.secondManifestPath)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", md.secondManifestPath, err)
	}

	log.Printf(
		`Paths:
	%s
	%s

`,
		firstAbsolutePath,
		secondAbsolutePath,
	)
	return nil
}

func (md *ManifestDiffer) openFirstFile() (*os.File, error) {
	firstFile, err := os.Open(md.firstManifestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open first file %q: %w", md.firstManifestPath, err)
	}

	md.firstHash = sha256.New()
	teeReader := io.TeeReader(firstFile, md.firstHash)
	md.firstReader = bufio.NewReaderSize(teeReader, readerBufferSize)
	return firstFile, nil
}

func (md *ManifestDiffer) openSecondFile() (*os.File, error) {
	secondFile, err := os.Open(md.secondManifestPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open second file %q: %w", md.secondManifestPath, err)
	}

	md.secondHash = sha256.New()
	teeReader := io.TeeReader(secondFile, md.secondHash)
	md.secondReader = bufio.NewReaderSize(teeReader, readerBufferSize)
	return secondFile, nil
}

func (*ManifestDiffer) closeFile(file *os.File) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close file %q: %w", file.Name(), err)
	}
	return nil
}

func (md *ManifestDiffer) createOutputFile() (*os.File, error) {
	if err := md.printOutputFile(); err != nil {
		return nil, err
	}

	outputFile, err := os.Create(md.filename)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file %q: %w", md.filename, err)
	}

	md.writer = bufio.NewWriterSize(outputFile, writerBufferSize)
	return outputFile, nil
}

func (md *ManifestDiffer) printOutputFile() error {
	absolutePath, err := filepath.Abs(md.filename)
	if err != nil {
		return fmt.Errorf("cannot return an absolute path for %q: %w", md.filename, err)
	}

	log.Printf(
		`Writing to:
	%s

`,
		absolutePath,
	)
	return nil
}

func (md *ManifestDiffer) closeOutputFile(outputFile *os.File) (err error) {
	if err = md.writer.Flush(); err != nil {
		err = fmt.Errorf("cannot flush output writer: %w", err)
	}
	if e := outputFile.Close(); e != nil {
		e = fmt.Errorf("cannot close output file %q: %w", outputFile.Name(), e)
		return errors.Join(err, e)
	}
	return err
}

func (md *ManifestDiffer) compare() error {
	first, firstOk, err := md.readNextLine(md.firstReader, md.firstManifestPath)
	if err != nil {
		return err
	}

	second, secondOk, err := md.readNextLine(md.secondReader, md.secondManifestPath)
	if err != nil {
		return err
	}

	isExtended := first.isExtended && second.isExtended
	var (
		added    []diffLine
		deleted  []diffLine
		modified []diffResult
	)
	for firstOk || secondOk {
		switch {
		case firstOk && secondOk && (first.raw == second.raw || (!isExtended && md.equalNotExtendedRecords(first.record, second.record))):
			first, firstOk, err = md.readNextLine(md.firstReader, md.firstManifestPath)
			if err != nil {
				return err
			}

			second, secondOk, err = md.readNextLine(md.secondReader, md.secondManifestPath)
			if err != nil {
				return err
			}
		case firstOk && secondOk && first.record.path == second.record.path:
			modified = append(modified, diffResult{diffType: diffTypeModified, first: first, second: second})
			first, firstOk, err = md.readNextLine(md.firstReader, md.firstManifestPath)
			if err != nil {
				return err
			}

			second, secondOk, err = md.readNextLine(md.secondReader, md.secondManifestPath)
			if err != nil {
				return err
			}
		case !secondOk || firstOk && first.record.path < second.record.path:
			deleted = append(deleted, first)
			first, firstOk, err = md.readNextLine(md.firstReader, md.firstManifestPath)
			if err != nil {
				return err
			}
		default:
			added = append(added, second)
			second, secondOk, err = md.readNextLine(md.secondReader, md.secondManifestPath)
			if err != nil {
				return err
			}
		}
	}

	results := make([]diffResult, 0, len(added)+len(deleted)+len(modified))
	results = append(results, md.matchMoved(deleted, added, isExtended)...)
	results = append(results, modified...)
	slices.SortFunc(results, md.sortResults)
	for i := range results {
		if err := md.writeResult(results[i], isExtended); err != nil {
			return err
		}
	}

	md.printHashEquality()

	return nil
}

func (*ManifestDiffer) readNextLine(reader *bufio.Reader, manifestPath string) (parsedLine diffLine, ok bool, err error) {
	line, ok, err := readNextLine(reader, manifestPath)
	if err != nil || !ok {
		return diffLine{}, ok, err
	}
	return diffLine{
		readLine:   line,
		isExtended: line.record.createdAt != "",
	}, true, nil
}

func (*ManifestDiffer) equalNotExtendedRecords(first, second fileRecord) bool {
	return first.hash == second.hash &&
		first.modifiedAt == second.modifiedAt &&
		first.size == second.size &&
		first.path == second.path
}

func (*ManifestDiffer) matchMoved(deleted, added []diffLine, isExtended bool) []diffResult {
	addedCount := len(added)
	addedIndicesBySignature := make(map[diffRecordSignature][]int, addedCount)
	for i := range added {
		signature := newDiffRecordSignature(added[i].record, isExtended)
		addedIndicesBySignature[signature] = append(addedIndicesBySignature[signature], i)
	}
	addedMatched := make([]bool, addedCount)
	results := make([]diffResult, 0, addedCount+len(deleted))
	for i := range deleted {
		signature := newDiffRecordSignature(deleted[i].record, isExtended)
		indices := addedIndicesBySignature[signature]
		matchedIndex := -1
		if len(indices) > 0 {
			matchedIndex = indices[0]
			indices = indices[1:]
		}
		addedIndicesBySignature[signature] = indices
		if matchedIndex < 0 {
			results = append(results, diffResult{diffType: diffTypeDeleted, first: deleted[i]})
			continue
		}

		addedMatched[matchedIndex] = true
		results = append(results, diffResult{diffType: diffTypeMoved, first: deleted[i], second: added[matchedIndex]})
	}
	for i := range added {
		if addedMatched[i] {
			continue
		}

		results = append(results, diffResult{diffType: diffTypeAdded, second: added[i]})
	}
	return results
}

func (md *ManifestDiffer) sortResults(first, second diffResult) int {
	if md.isGrouped {
		result := cmp.Compare(first.diffType, second.diffType)
		if result != 0 {
			return result
		}
	}

	firstPath := md.resultPath(first)
	secondPath := md.resultPath(second)
	result := strings.Compare(firstPath, secondPath)
	if result != 0 {
		return result
	}
	if !md.isGrouped {
		return cmp.Compare(first.diffType, second.diffType)
	}
	return 0
}

func (*ManifestDiffer) resultPath(result diffResult) string {
	if result.second.raw != "" {
		return result.second.record.path
	}
	if result.first.raw != "" {
		return result.first.record.path
	}
	return ""
}

func (md *ManifestDiffer) writeResult(result diffResult, isExtended bool) error {
	switch result.diffType {
	case diffTypeAdded:
		return md.writeRecord(result.second.record, isExtended, markAdded)
	case diffTypeDeleted:
		return md.writeRecord(result.first.record, isExtended, markDeleted)
	case diffTypeMoved:
		return md.writeChangedRecord(result.first.record, result.second.record, isExtended, markMoved)
	case diffTypeModified:
		return md.writeChangedRecord(result.first.record, result.second.record, isExtended, markModified)
	}
	return fmt.Errorf("unknown diff type: %d", result.diffType)
}

func (md *ManifestDiffer) writeRecord(record fileRecord, isExtended bool, mark string) error {
	_, err := fmt.Fprintf(
		md.writer,
		"%s%s %s%s\n",
		md.markColor(mark),
		mark,
		formatRecord(record, isExtended, sizeWidth),
		ansiReset,
	)
	return err
}

func (*ManifestDiffer) markColor(mark string) string {
	switch mark {
	case markAdded:
		return ansiSoftGreenBackground
	case markDeleted:
		return ansiSoftRedBackground
	}
	return ""
}

func (md *ManifestDiffer) writeChangedRecord(first, second fileRecord, isExtended bool, mark string) error {
	firstFields := md.changedRecordFields(second, first, isExtended, ansiSoftPurpleBackground, false)
	secondFields := md.changedRecordFields(first, second, isExtended, ansiGray, true)
	if _, err := fmt.Fprintln(md.writer, mark+" "+strings.Join(firstFields, "\t")); err != nil {
		return err
	}

	_, err := fmt.Fprintln(md.writer, "  "+strings.Join(secondFields, "\t"))
	return err
}

func (md *ManifestDiffer) changedRecordFields(record, other fileRecord, isExtended bool, color string, changedOnly bool) []string {
	fields := make([]string, 0, extendedRecordFieldCount)
	fields = append(fields, md.changedStringField(record.hash, other.hash, color, changedOnly))
	if isExtended {
		fields = append(
			fields,
			md.changedTimeField(record.createdAt, other.createdAt, color, changedOnly),
			md.changedTimeField(record.modifiedAt, other.modifiedAt, color, changedOnly),
			md.changedTimeField(record.accessedAt, other.accessedAt, color, changedOnly),
			md.changedTimeField(record.changedAt, other.changedAt, color, changedOnly),
		)
	} else {
		fields = append(fields, md.changedTimeField(record.modifiedAt, other.modifiedAt, color, changedOnly))
	}
	fields = append(
		fields,
		md.changedSizeField(record.size, other.size, sizeWidth, color, changedOnly),
		md.changedPathField(record.path, other.path, color, changedOnly),
	)
	return fields
}

func (*ManifestDiffer) changedStringField(value, other, color string, changedOnly bool) string {
	if value == other {
		if changedOnly {
			return strings.Repeat(" ", len([]rune(value)))
		}
		return value
	}
	return color + value + ansiReset
}

func (*ManifestDiffer) changedTimeField(value, other, color string, changedOnly bool) string {
	if value == other {
		if changedOnly {
			return strings.Repeat(" ", len([]rune(value)))
		}
		return value
	}
	return color + value + ansiReset
}

func (*ManifestDiffer) changedSizeField(value, other int64, width int, color string, changedOnly bool) string {
	if value == other {
		if changedOnly {
			return strings.Repeat(" ", width)
		}
		return fmt.Sprintf("%*d", width, value)
	}

	valueString := strconv.FormatInt(value, 10)
	return strings.Repeat(" ", max(0, width-len(valueString))) + color + valueString + ansiReset
}

func (md *ManifestDiffer) changedPathField(value, other, color string, changedOnly bool) string {
	if value == other {
		if changedOnly {
			return strings.Repeat(" ", len([]rune(value)))
		}
		return value
	}

	valueRunes := []rune(value)
	otherRunes := []rune(other)
	prefixLength := md.commonRunePrefixLength(valueRunes, otherRunes)
	suffixLength := md.commonRuneSuffixLength(valueRunes[prefixLength:], otherRunes[prefixLength:])
	changedEnd := len(valueRunes) - suffixLength
	var sb strings.Builder
	if changedOnly {
		sb.WriteString(strings.Repeat(" ", prefixLength))
	} else {
		sb.WriteString(string(valueRunes[:prefixLength]))
	}
	if prefixLength < changedEnd {
		sb.WriteString(color + string(valueRunes[prefixLength:changedEnd]) + ansiReset)
	}
	if suffixLength > 0 {
		if changedOnly {
			sb.WriteString(strings.Repeat(" ", suffixLength))
		} else {
			sb.WriteString(string(valueRunes[changedEnd:]))
		}
	}
	return sb.String()
}

func (*ManifestDiffer) commonRunePrefixLength(first, second []rune) int {
	firstCount := len(first)
	secondCount := len(second)
	if secondCount < firstCount {
		firstCount = secondCount
	}
	for i := 0; i < firstCount; i++ {
		if first[i] != second[i] {
			return i
		}
	}
	return firstCount
}

func (*ManifestDiffer) commonRuneSuffixLength(first, second []rune) int {
	firstCount := len(first)
	secondCount := len(second)
	if secondCount < firstCount {
		firstCount = secondCount
	}
	for i := 0; i < firstCount; i++ {
		if first[len(first)-1-i] != second[secondCount-1-i] {
			return i
		}
	}
	return firstCount
}

func (md *ManifestDiffer) printHashEquality() {
	firstSum := md.firstHash.Sum(nil)
	firstHash := hex.EncodeToString(firstSum)
	secondSum := md.secondHash.Sum(nil)
	secondHash := hex.EncodeToString(secondSum)
	if firstHash == secondHash {
		log.Println("Manifest hashes are equal!")
		return
	}

	log.Println("Manifest hashes differ.")
}

func (*ManifestDiffer) printDone() {
	log.Println("Hash lists compared!")
}

func NewManifestDiffer(firstManifestPath, secondManifestPath string, isGrouped bool) ManifestDiffer {
	firstManifestPath = filepath.Clean(firstManifestPath)
	secondManifestPath = filepath.Clean(secondManifestPath)
	return ManifestDiffer{
		firstManifestPath:  firstManifestPath,
		secondManifestPath: secondManifestPath,
		isGrouped:          isGrouped,
		filename:           filenameForDiff(isGrouped),
	}
}

func filenameForDiff(isGrouped bool) string {
	createdAt := time.Now().Format(filenameDateTimeLayout)
	grouped := ""
	if isGrouped {
		grouped = " grouped"
	}
	return createdAt + grouped + ".diff"
}

type diffRecordSignature struct {
	hash       string
	createdAt  string
	modifiedAt string
	accessedAt string
	changedAt  string
	size       int64
}

func newDiffRecordSignature(record fileRecord, isExtended bool) diffRecordSignature {
	signature := diffRecordSignature{
		hash:       record.hash,
		modifiedAt: record.modifiedAt,
		size:       record.size,
	}
	if isExtended {
		signature.createdAt = record.createdAt
		signature.accessedAt = record.accessedAt
		signature.changedAt = record.changedAt
	}
	return signature
}
