// Package transfer encodes and decodes documents for import and export:
// MongoDB Extended JSON (relaxed or canonical) as a JSON array or one
// document per line, CSV/TSV with field mapping, and BSON (the format of
// mongodump .bson files). Everything streams: no format needs the whole
// data set in memory.
package transfer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Format is a data format.
type Format string

const (
	JSON   Format = "json"   // JSON array of Extended JSON documents
	NDJSON Format = "ndjson" // one Extended JSON document per line (mongoexport default)
	CSV    Format = "csv"
	TSV    Format = "tsv"
	BSON   Format = "bson" // concatenated BSON documents (mongodump .bson)
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case JSON, NDJSON, CSV, TSV, BSON:
		return f, nil
	case "":
		return NDJSON, nil
	}
	return "", fmt.Errorf("unknown format %q (json, ndjson, csv, tsv or bson)", s)
}

// Extension returns the file extension of a format.
func (f Format) Extension() string {
	if f == NDJSON {
		return "json"
	}
	return string(f)
}

// ContentType returns the MIME type of a format.
func (f Format) ContentType() string {
	switch f {
	case JSON:
		return "application/json"
	case NDJSON:
		return "application/x-ndjson"
	case CSV:
		return "text/csv; charset=utf-8"
	case TSV:
		return "text/tab-separated-values; charset=utf-8"
	}
	return "application/octet-stream"
}

// ExportOptions configures an Encoder.
type ExportOptions struct {
	Format Format
	// Canonical writes canonical Extended JSON (exact types, for round trips
	// with other tools); relaxed is easier to read.
	Canonical bool
	// Fields are the dotted paths of CSV/TSV columns. Without them, the
	// columns are the fields of the first document (nested documents are
	// flattened to dotted paths).
	Fields []string
}

// Encoder writes documents in a format.
type Encoder interface {
	Write(doc bson.Raw) error
	// Close writes the format's trailer (and flushes); it does not close the
	// underlying writer.
	Close() error
}

// NewEncoder returns an encoder writing to w.
func NewEncoder(w io.Writer, o ExportOptions) (Encoder, error) {
	switch o.Format {
	case JSON, NDJSON:
		return &jsonEncoder{w: bufio.NewWriterSize(w, 64<<10), array: o.Format == JSON, canonical: o.Canonical}, nil
	case CSV, TSV:
		cw := csv.NewWriter(w)
		if o.Format == TSV {
			cw.Comma = '\t'
		}
		return &csvEncoder{w: cw, fields: o.Fields}, nil
	case BSON:
		return &bsonEncoder{w: bufio.NewWriterSize(w, 64<<10)}, nil
	}
	return nil, fmt.Errorf("unknown format %q", o.Format)
}

type jsonEncoder struct {
	w         *bufio.Writer
	array     bool
	canonical bool
	n         int
}

func (e *jsonEncoder) Write(doc bson.Raw) error {
	b, err := bson.MarshalExtJSON(doc, e.canonical, false)
	if err != nil {
		return err
	}
	switch {
	case e.array && e.n == 0:
		_, _ = e.w.WriteString("[\n")
	case e.array:
		_, _ = e.w.WriteString(",\n")
	}
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	if !e.array {
		_ = e.w.WriteByte('\n')
	}
	e.n++
	return nil
}

func (e *jsonEncoder) Close() error {
	if e.array {
		if e.n == 0 {
			_, _ = e.w.WriteString("[")
		}
		_, _ = e.w.WriteString("\n]\n")
	}
	return e.w.Flush()
}

type bsonEncoder struct{ w *bufio.Writer }

func (e *bsonEncoder) Write(doc bson.Raw) error { _, err := e.w.Write(doc); return err }
func (e *bsonEncoder) Close() error             { return e.w.Flush() }

type csvEncoder struct {
	w      *csv.Writer
	fields []string
	header bool
}

func (e *csvEncoder) Write(doc bson.Raw) error {
	if !e.header {
		if len(e.fields) == 0 {
			e.fields = Paths(doc, 3)
		}
		if err := e.w.Write(e.fields); err != nil {
			return err
		}
		e.header = true
	}
	row := make([]string, len(e.fields))
	for i, f := range e.fields {
		v, err := doc.LookupErr(strings.Split(f, ".")...)
		if err == nil {
			row[i] = CellString(v)
		}
	}
	return e.w.Write(row)
}

func (e *csvEncoder) Close() error {
	if !e.header && len(e.fields) > 0 {
		_ = e.w.Write(e.fields)
	}
	e.w.Flush()
	return e.w.Error()
}

// Paths lists the field paths of doc, flattening embedded documents up to
// depth levels (arrays are kept as one value).
func Paths(doc bson.Raw, depth int) []string {
	var out []string
	var walk func(d bson.Raw, prefix string, level int)
	walk = func(d bson.Raw, prefix string, level int) {
		els, err := d.Elements()
		if err != nil {
			return
		}
		for _, el := range els {
			k := prefix + el.Key()
			if v := el.Value(); v.Type == bson.TypeEmbeddedDocument && level < depth {
				walk(v.Document(), k+".", level+1)
				continue
			}
			out = append(out, k)
		}
	}
	walk(doc, "", 1)
	return out
}

// CellString renders a value for a CSV cell: plain text for scalars,
// relaxed Extended JSON for documents, arrays and binary types.
func CellString(v bson.RawValue) string {
	switch v.Type {
	case bson.TypeString:
		return v.StringValue()
	case bson.TypeInt32:
		return strconv.FormatInt(int64(v.Int32()), 10)
	case bson.TypeInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case bson.TypeDouble:
		f := v.Double()
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return strconv.FormatFloat(f, 'g', -1, 64)
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	case bson.TypeBoolean:
		return strconv.FormatBool(v.Boolean())
	case bson.TypeDateTime:
		return time.UnixMilli(v.DateTime()).UTC().Format("2006-01-02T15:04:05.000Z")
	case bson.TypeObjectID:
		return v.ObjectID().Hex()
	case bson.TypeDecimal128:
		return v.Decimal128().String()
	case bson.TypeNull, bson.TypeUndefined:
		return ""
	}
	// Documents, arrays and special types as Extended JSON.
	d := bson.D{{Key: "v", Value: v}}
	b, err := bson.MarshalExtJSON(d, false, false)
	if err != nil {
		return ""
	}
	s := string(b)
	// {"v":<value>}
	return strings.TrimSuffix(strings.TrimPrefix(s, `{"v":`), "}")
}

// ErrTooLarge means a record exceeded the size limit.
var ErrTooLarge = errors.New("record exceeds the maximum document size")
