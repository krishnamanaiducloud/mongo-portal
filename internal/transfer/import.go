package transfer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MaxRecordBytes caps one input record (MongoDB's document limit plus
// encoding overhead).
const MaxRecordBytes = 24 << 20

// FieldMap maps one CSV/TSV column to a document field.
type FieldMap struct {
	Column string `json:"column"`
	// Field is the dotted target path; empty uses the column name.
	Field string `json:"field,omitempty"`
	// Type is auto (default), string, int, long, double, decimal, bool,
	// date or objectId.
	Type string `json:"type,omitempty"`
	Skip bool   `json:"skip,omitempty"`
}

var fieldTypes = []string{"", "auto", "string", "int", "long", "double", "decimal", "bool", "date", "objectId"}

// ImportOptions configures a Decoder.
type ImportOptions struct {
	Format  Format
	Mapping []FieldMap
	// KeepBlanks keeps empty CSV cells as empty strings (default: omit).
	KeepBlanks bool
}

// Validate checks the options.
func (o ImportOptions) Validate() error {
	for _, m := range o.Mapping {
		if m.Column == "" || len(m.Column) > 256 || len(m.Field) > 256 {
			return errors.New("mapping columns must be named (at most 256 characters)")
		}
		if !slices.Contains(fieldTypes, m.Type) {
			return fmt.Errorf("mapping type %q is not supported", m.Type)
		}
		if f := m.Field; f != "" && (strings.HasPrefix(f, "$") || strings.Contains(f, "..") || strings.HasPrefix(f, ".") || strings.HasSuffix(f, ".")) {
			return fmt.Errorf("mapping field %q is not a valid field path", f)
		}
	}
	return nil
}

// RecordError is a bad input record; the import can skip it.
type RecordError struct {
	Record int64  `json:"record"`
	Msg    string `json:"message"`
}

func (e *RecordError) Error() string { return fmt.Sprintf("record %d: %s", e.Record, e.Msg) }

// Decoder reads documents.
type Decoder interface {
	// Next returns the next document. A *RecordError means the record is
	// unusable but decoding can continue; io.EOF ends the input; any other
	// error is fatal.
	Next() (bson.D, error)
	// Record is the 1-based number of the last record read.
	Record() int64
	// Columns returns the CSV/TSV header (nil for other formats).
	Columns() []string
}

// Decompress returns r, transparently un-gzipped when it starts with the
// gzip magic number.
func Decompress(r io.Reader) (io.Reader, bool, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(2)
	if err == nil && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, true, fmt.Errorf("gzip: %w", err)
		}
		return gz, true, nil
	}
	return br, false, nil
}

// NewDecoder returns a decoder for r (already decompressed).
func NewDecoder(r io.Reader, o ImportOptions) (Decoder, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	switch o.Format {
	case NDJSON:
		br := bufio.NewReaderSize(r, 64<<10)
		return &lineDecoder{r: br}, nil
	case JSON:
		return newJSONDecoder(r)
	case CSV, TSV:
		cr := csv.NewReader(r)
		if o.Format == TSV {
			cr.Comma = '\t'
			cr.LazyQuotes = true
		}
		cr.FieldsPerRecord = -1
		cr.ReuseRecord = true
		return &csvDecoder{r: cr, opts: o}, nil
	case BSON:
		return &bsonDecoder{r: bufio.NewReaderSize(r, 64<<10)}, nil
	}
	return nil, fmt.Errorf("unknown format %q", o.Format)
}

func parseDoc(b []byte, rec int64) (bson.D, error) {
	var d bson.D
	if err := bson.UnmarshalExtJSON(b, false, &d); err != nil {
		return nil, &RecordError{Record: rec, Msg: "not a valid (Extended) JSON document: " + shortErr(err)}
	}
	return d, nil
}

// lineDecoder reads one Extended JSON document per line.
type lineDecoder struct {
	r   *bufio.Reader
	rec int64
}

func (d *lineDecoder) Next() (bson.D, error) {
	for {
		line, err := readLine(d.r)
		if len(bytes.TrimSpace(line)) == 0 {
			if err != nil {
				return nil, err
			}
			continue
		}
		d.rec++
		if errors.Is(err, ErrTooLarge) {
			return nil, &RecordError{Record: d.rec, Msg: ErrTooLarge.Error()}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return parseDoc(line, d.rec)
	}
}

func (d *lineDecoder) Record() int64     { return d.rec }
func (d *lineDecoder) Columns() []string { return nil }

// readLine reads one line, bounded by MaxRecordBytes. An overlong line is
// consumed and reported as ErrTooLarge.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxRecordBytes {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return []byte("x"), ErrTooLarge
		}
		buf = append(buf, chunk...)
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil:
			return buf, err
		}
		return buf, nil
	}
}

// jsonDecoder reads a JSON array of documents, or documents one after the
// other (not necessarily one per line).
type jsonDecoder struct {
	dec   *json.Decoder
	array bool
	rec   int64
	done  bool
}

func newJSONDecoder(r io.Reader) (*jsonDecoder, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	first := byte(0)
	for {
		b, err := br.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return &jsonDecoder{done: true}, nil
			}
			return nil, err
		}
		if c := b[0]; c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == 0xEF || c == 0xBB || c == 0xBF {
			_, _ = br.ReadByte() // whitespace and a UTF-8 byte order mark
			continue
		}
		first = b[0]
		break
	}
	d := &jsonDecoder{dec: json.NewDecoder(br)}
	if first == '[' {
		if _, err := d.dec.Token(); err != nil {
			return nil, err
		}
		d.array = true
	}
	return d, nil
}

func (d *jsonDecoder) Next() (bson.D, error) {
	if d.done || (d.array && !d.dec.More()) {
		d.done = true
		return nil, io.EOF
	}
	var raw json.RawMessage
	if err := d.dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) && !d.array {
			d.done = true
			return nil, io.EOF
		}
		// JSON syntax errors leave the stream unusable.
		return nil, fmt.Errorf("invalid JSON after record %d: %s", d.rec, shortErr(err))
	}
	d.rec++
	if len(raw) > MaxRecordBytes {
		return nil, &RecordError{Record: d.rec, Msg: ErrTooLarge.Error()}
	}
	return parseDoc(raw, d.rec)
}

func (d *jsonDecoder) Record() int64     { return d.rec }
func (d *jsonDecoder) Columns() []string { return nil }

// bsonDecoder reads length-prefixed BSON documents.
type bsonDecoder struct {
	r   *bufio.Reader
	rec int64
}

func (d *bsonDecoder) Next() (bson.D, error) {
	var lenb [4]byte
	if _, err := io.ReadFull(d.r, lenb[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("truncated BSON after record %d", d.rec)
	}
	n := int64(binary.LittleEndian.Uint32(lenb[:]))
	if n < 5 || n > MaxRecordBytes {
		return nil, fmt.Errorf("invalid BSON document length %d after record %d", n, d.rec)
	}
	buf := make([]byte, n)
	copy(buf, lenb[:])
	if _, err := io.ReadFull(d.r, buf[4:]); err != nil {
		return nil, fmt.Errorf("truncated BSON document after record %d", d.rec)
	}
	d.rec++
	raw := bson.Raw(buf)
	if err := raw.Validate(); err != nil {
		return nil, &RecordError{Record: d.rec, Msg: "invalid BSON document"}
	}
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return nil, &RecordError{Record: d.rec, Msg: "invalid BSON document"}
	}
	return doc, nil
}

func (d *bsonDecoder) Record() int64     { return d.rec }
func (d *bsonDecoder) Columns() []string { return nil }

// csvDecoder reads CSV/TSV with a header line.
type csvDecoder struct {
	r       *csv.Reader
	opts    ImportOptions
	columns []string
	plan    []FieldMap
	rec     int64
}

func (d *csvDecoder) Columns() []string { return d.columns }
func (d *csvDecoder) Record() int64     { return d.rec }

func (d *csvDecoder) header() error {
	h, err := d.r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("cannot read the header line: %s", shortErr(err))
	}
	d.columns = make([]string, len(h))
	for i, c := range h {
		d.columns[i] = strings.TrimSpace(strings.TrimPrefix(c, "\uFEFF"))
	}
	byCol := map[string]FieldMap{}
	for _, m := range d.opts.Mapping {
		byCol[m.Column] = m
	}
	d.plan = make([]FieldMap, len(d.columns))
	for i, c := range d.columns {
		m, ok := byCol[c]
		if !ok {
			m = FieldMap{Column: c}
		}
		if m.Field == "" {
			m.Field = c
		}
		if c == "" || strings.HasPrefix(m.Field, "$") {
			m.Skip = true
		}
		d.plan[i] = m
	}
	return nil
}

func (d *csvDecoder) Next() (bson.D, error) {
	if d.columns == nil {
		if err := d.header(); err != nil {
			return nil, err
		}
	}
	row, err := d.r.Read()
	if errors.Is(err, io.EOF) {
		return nil, io.EOF
	}
	d.rec++
	if err != nil {
		var pe *csv.ParseError
		if errors.As(err, &pe) && !errors.Is(pe.Err, csv.ErrFieldCount) {
			return nil, &RecordError{Record: d.rec, Msg: shortErr(err)}
		}
		if !errors.As(err, &pe) {
			return nil, err
		}
	}
	doc := bson.D{}
	for i, cell := range row {
		if i >= len(d.plan) {
			return nil, &RecordError{Record: d.rec, Msg: "more cells than header columns"}
		}
		m := d.plan[i]
		if m.Skip || (cell == "" && !d.opts.KeepBlanks) {
			continue
		}
		v, err := Convert(cell, m.Type)
		if err != nil {
			return nil, &RecordError{Record: d.rec, Msg: fmt.Sprintf("column %q: %s", m.Column, err.Error())}
		}
		doc = setPath(doc, strings.Split(m.Field, "."), v)
	}
	return doc, nil
}

// setPath sets a dotted path in a document, creating embedded documents.
func setPath(d bson.D, path []string, v any) bson.D {
	for i := range d {
		if d[i].Key == path[0] {
			if len(path) == 1 {
				d[i].Value = v
				return d
			}
			sub, _ := d[i].Value.(bson.D)
			d[i].Value = setPath(sub, path[1:], v)
			return d
		}
	}
	if len(path) == 1 {
		return append(d, bson.E{Key: path[0], Value: v})
	}
	return append(d, bson.E{Key: path[0], Value: setPath(bson.D{}, path[1:], v)})
}

// Convert parses a CSV cell to a typed value.
func Convert(cell, typ string) (any, error) {
	switch typ {
	case "", "auto":
		if i, err := strconv.ParseInt(cell, 10, 64); err == nil && !leadingZero(cell) {
			if i >= -1<<31 && i < 1<<31 {
				return int32(i), nil
			}
			return i, nil
		}
		if f, err := strconv.ParseFloat(cell, 64); err == nil && strings.ContainsAny(cell, ".eE") && !leadingZero(cell) {
			return f, nil
		}
		switch cell {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return cell, nil
	case "string":
		return cell, nil
	case "int":
		i, err := strconv.ParseInt(strings.TrimSpace(cell), 10, 32)
		if err != nil {
			return nil, errors.New("not a 32-bit integer")
		}
		return int32(i), nil
	case "long":
		i, err := strconv.ParseInt(strings.TrimSpace(cell), 10, 64)
		if err != nil {
			return nil, errors.New("not a 64-bit integer")
		}
		return i, nil
	case "double":
		f, err := strconv.ParseFloat(strings.TrimSpace(cell), 64)
		if err != nil {
			return nil, errors.New("not a number")
		}
		return f, nil
	case "decimal":
		d, err := bson.ParseDecimal128(strings.TrimSpace(cell))
		if err != nil {
			return nil, errors.New("not a decimal")
		}
		return d, nil
	case "bool":
		b, err := strconv.ParseBool(strings.TrimSpace(cell))
		if err != nil {
			return nil, errors.New("not true or false")
		}
		return b, nil
	case "date":
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, strings.TrimSpace(cell)); err == nil {
				return bson.NewDateTimeFromTime(t), nil
			}
		}
		return nil, errors.New("not an ISO 8601 date")
	case "objectId":
		id, err := bson.ObjectIDFromHex(strings.TrimSpace(cell))
		if err != nil {
			return nil, errors.New("not an ObjectId")
		}
		return id, nil
	}
	return nil, fmt.Errorf("unknown type %q", typ)
}

// leadingZero keeps values like zip codes ("01234") as strings.
func leadingZero(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return len(s) > 1 && s[0] == '0' && s[1] != '.'
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
