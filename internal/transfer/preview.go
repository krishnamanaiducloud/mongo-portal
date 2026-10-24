package transfer

import (
	"encoding/json"
	"errors"
	"io"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// PreviewResult shows how an import file will be read.
type PreviewResult struct {
	Format    Format            `json:"format"`
	Gzip      bool              `json:"gzip"`
	Documents []json.RawMessage `json:"documents"`
	Columns   []string          `json:"columns,omitempty"`
	// Types are the types auto-detection chose per column (first rows).
	Types  map[string]string `json:"types,omitempty"`
	Errors []RecordError     `json:"errors"`
	// Partial is true when the sample ended inside a record (expected for
	// a prefix of a large file).
	Partial bool `json:"partial"`
}

// Preview decodes up to n documents of a file prefix.
func Preview(r io.Reader, o ImportOptions, n int) (*PreviewResult, error) {
	dr, gz, err := Decompress(r)
	if err != nil {
		return nil, err
	}
	dec, err := NewDecoder(dr, o)
	if err != nil {
		return nil, err
	}
	res := &PreviewResult{Format: o.Format, Gzip: gz, Documents: []json.RawMessage{}, Errors: []RecordError{}}
	types := map[string]string{}
	for len(res.Documents) < n {
		doc, err := dec.Next()
		var re *RecordError
		switch {
		case errors.Is(err, io.EOF):
			n = 0
		case errors.Is(err, io.ErrUnexpectedEOF):
			res.Partial = true
			n = 0
		case errors.As(err, &re):
			res.Errors = append(res.Errors, *re)
			if len(res.Errors) >= 20 {
				n = 0
			}
		case err != nil:
			// A fatal error in a prefix is usually a cut-off last record.
			if len(res.Documents) == 0 {
				return nil, err
			}
			res.Partial = true
			n = 0
		default:
			b, merr := bson.MarshalExtJSON(doc, false, false)
			if merr != nil {
				return nil, merr
			}
			res.Documents = append(res.Documents, b)
			for _, e := range doc {
				if _, seen := types[e.Key]; !seen {
					types[e.Key] = typeName(e.Value)
				}
			}
		}
	}
	if cols := dec.Columns(); cols != nil {
		res.Columns, res.Types = cols, types
	}
	return res, nil
}

func typeName(v any) string {
	switch v.(type) {
	case int32:
		return "int"
	case int64:
		return "long"
	case float64:
		return "double"
	case bool:
		return "bool"
	case bson.D:
		return "object"
	case bson.Decimal128:
		return "decimal"
	case bson.DateTime:
		return "date"
	case bson.ObjectID:
		return "objectId"
	}
	return "string"
}
