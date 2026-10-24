package transfer

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func sampleDocs(t *testing.T) []bson.Raw {
	t.Helper()
	oid, _ := bson.ObjectIDFromHex("507f1f77bcf86cd799439011")
	dec, _ := bson.ParseDecimal128("9.99")
	docs := []bson.D{
		{{Key: "_id", Value: oid}, {Key: "name", Value: "Widget, large"}, {Key: "qty", Value: int32(5)}, {Key: "price", Value: dec},
			{Key: "big", Value: int64(1) << 40}, {Key: "when", Value: bson.NewDateTimeFromTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))},
			{Key: "tags", Value: bson.A{"a", "b"}}, {Key: "dim", Value: bson.D{{Key: "w", Value: 1.5}, {Key: "h", Value: int32(2)}}}},
		{{Key: "_id", Value: int32(2)}, {Key: "name", Value: "line\nbreak \"quoted\""}, {Key: "qty", Value: int32(0)}},
	}
	out := make([]bson.Raw, len(docs))
	for i, d := range docs {
		b, err := bson.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func export(t *testing.T, o ExportOptions, docs []bson.Raw) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := NewEncoder(&buf, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		if err := enc.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func importAll(t *testing.T, data []byte, o ImportOptions) ([]bson.D, []RecordError) {
	t.Helper()
	r, _, err := Decompress(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder(r, o)
	if err != nil {
		t.Fatal(err)
	}
	var docs []bson.D
	var bad []RecordError
	for {
		d, err := dec.Next()
		var re *RecordError
		switch {
		case errors.Is(err, io.EOF):
			return docs, bad
		case errors.As(err, &re):
			bad = append(bad, *re)
		case err != nil:
			t.Fatalf("decode: %v", err)
		default:
			docs = append(docs, d)
		}
	}
}

// Extended JSON and BSON round trips keep every BSON type exactly.
func TestRoundTripsKeepTypes(t *testing.T) {
	src := sampleDocs(t)
	for _, c := range []struct {
		name string
		o    ExportOptions
	}{
		{"ndjson canonical", ExportOptions{Format: NDJSON, Canonical: true}},
		{"json array canonical", ExportOptions{Format: JSON, Canonical: true}},
		{"bson", ExportOptions{Format: BSON}},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := export(t, c.o, src)
			docs, bad := importAll(t, data, ImportOptions{Format: c.o.Format})
			if len(bad) != 0 || len(docs) != len(src) {
				t.Fatalf("got %d docs, %v", len(docs), bad)
			}
			for i, d := range docs {
				b, _ := bson.Marshal(d)
				if !bytes.Equal(b, src[i]) {
					t.Errorf("doc %d changed:\n got %v\nwant %v", i, bson.Raw(b), src[i])
				}
			}
		})
	}
	// Relaxed JSON is readable: plain numbers and ISO dates.
	rel := string(export(t, ExportOptions{Format: NDJSON}, src[:1]))
	if !strings.Contains(rel, `"qty":5`) || !strings.Contains(rel, `"$date":"2026-01-02T03:04:05Z"`) {
		t.Errorf("relaxed output: %s", rel)
	}
	if empty := string(export(t, ExportOptions{Format: JSON}, nil)); strings.TrimSpace(empty) != "[\n]" {
		t.Errorf("empty array: %q", empty)
	}
}

func TestCSVExportAndImportWithMapping(t *testing.T) {
	src := sampleDocs(t)
	out := string(export(t, ExportOptions{Format: CSV}, src))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[0] != "_id,name,qty,price,big,when,tags,dim.w,dim.h" {
		t.Fatalf("header: %s", lines[0])
	}
	if !strings.Contains(lines[1], `507f1f77bcf86cd799439011,"Widget, large",5,9.99,1099511627776,2026-01-02T03:04:05.000Z,"[""a"",""b""]",1.5,2`) {
		t.Fatalf("row: %s", lines[1])
	}
	// Selected fields and TSV.
	tsv := string(export(t, ExportOptions{Format: TSV, Fields: []string{"name", "dim.h", "missing"}}, src[:1]))
	if tsv != "name\tdim.h\tmissing\nWidget, large\t2\t\n" {
		t.Fatalf("tsv: %q", tsv)
	}

	in := "id,zip,amount,ok,day,nested.x,ignored\n" +
		"507f1f77bcf86cd799439011,01234,12.50,true,2026-03-04,7,zzz\n" +
		"bad-id,9,1,false,,8,\n"
	docs, bad := importAll(t, []byte(in), ImportOptions{Format: CSV, Mapping: []FieldMap{
		{Column: "id", Field: "_id", Type: "objectId"},
		{Column: "amount", Type: "decimal"},
		{Column: "day", Type: "date"},
		{Column: "ignored", Skip: true},
	}})
	if len(docs) != 1 || len(bad) != 1 || bad[0].Record != 2 || !strings.Contains(bad[0].Msg, "ObjectId") {
		t.Fatalf("docs %v bad %v", docs, bad)
	}
	got, _ := bson.MarshalExtJSON(docs[0], true, false)
	want := `{"_id":{"$oid":"507f1f77bcf86cd799439011"},"zip":"01234","amount":{"$numberDecimal":"12.50"},"ok":true,"day":{"$date":{"$numberLong":"1772582400000"}},"nested":{"x":{"$numberInt":"7"}}}`
	if string(got) != want {
		t.Fatalf("doc:\n got %s\nwant %s", got, want)
	}
}

func TestGzipAndBadRecords(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = io.WriteString(gz, "{\"a\":1}\n\nnot json\n{\"$where\":1}\n{\"b\":{\"$numberLong\":\"5\"}}\n")
	_ = gz.Close()
	docs, bad := importAll(t, buf.Bytes(), ImportOptions{Format: NDJSON})
	if len(docs) != 3 || len(bad) != 1 || bad[0].Record != 2 {
		t.Fatalf("docs %d bad %v", len(docs), bad)
	}
	// Concatenated JSON documents (not an array) are accepted too.
	docs, bad = importAll(t, []byte("\uFEFF {\"a\":1} {\"a\":2}\n{\"a\":3}"), ImportOptions{Format: JSON})
	if len(docs) != 3 || len(bad) != 0 {
		t.Fatalf("concatenated: %d %v", len(docs), bad)
	}
	// Truncated BSON is fatal, not silently ignored.
	b, _ := bson.Marshal(bson.D{{Key: "a", Value: 1}})
	dec, _ := NewDecoder(bytes.NewReader(append(b, b[:7]...)), ImportOptions{Format: BSON})
	if _, err := dec.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.Next(); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("truncated bson: %v", err)
	}
}

func TestPreviewAndValidation(t *testing.T) {
	res, err := Preview(strings.NewReader("name,qty\nwidget,5\ngadget,7.5\n\"cut"), ImportOptions{Format: CSV}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 2 || res.Types["qty"] != "int" || res.Types["name"] != "string" || len(res.Columns) != 2 {
		t.Fatalf("preview: %+v", res)
	}
	for _, m := range []FieldMap{{Column: ""}, {Column: "a", Type: "uuid"}, {Column: "a", Field: "$set"}, {Column: "a", Field: "x..y"}} {
		if (ImportOptions{Format: CSV, Mapping: []FieldMap{m}}).Validate() == nil {
			t.Errorf("mapping %+v should be rejected", m)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("unknown format must be rejected")
	}
}
