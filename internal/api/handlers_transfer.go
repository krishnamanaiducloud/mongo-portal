package api

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/query"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/transfer"
)

// Exports stream straight from a MongoDB cursor to the response, so the
// browser's download shows progress and cancelling the download cancels the
// cursor. They read with the user's own session: what MongoDB and portal
// RBAC allow is what can be exported. An export is not a backup: documents
// are read over time without a point-in-time snapshot.

const previewBytes = 1 << 20

// longWrite lifts the server write deadline for a streaming response; the
// stream ends when the client goes away or the request context ends.
func longWrite(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
}

func (s *Server) transferOff(w http.ResponseWriter, r *http.Request) bool {
	if !s.Config.TransferEnabled() {
		writeError(w, r, http.StatusNotFound, "transfer_disabled", "Import and export are turned off on this portal")
		return true
	}
	return false
}

// exportRequest is parsed from query parameters (exports are downloads).
type exportRequest struct {
	format    transfer.Format
	canonical bool
	gzip      bool
	fields    []string
	spec      *findSpec
	limit     int64
}

func (s *Server) parseExport(r *http.Request) (*exportRequest, error) {
	q := r.URL.Query()
	f, err := transfer.ParseFormat(q.Get("format"))
	if err != nil {
		return nil, err
	}
	spec, err := s.buildFind(q.Get("filter"), q.Get("projection"), q.Get("sort"))
	if err != nil {
		return nil, err
	}
	er := &exportRequest{format: f, canonical: q.Get("ejson") == "canonical", gzip: q.Get("gzip") == "true", spec: spec, limit: s.Config.Transfer.MaxExportDocuments}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, errors.New("limit must be a positive number")
		}
		er.limit = min(n, er.limit)
	}
	if v := strings.TrimSpace(q.Get("fields")); v != "" {
		for _, fld := range strings.Split(v, ",") {
			fld = strings.TrimSpace(fld)
			if fld == "" || len(fld) > 256 || strings.HasPrefix(fld, "$") {
				return nil, errors.New("fields must be a comma-separated list of field paths")
			}
			er.fields = append(er.fields, fld)
		}
		if len(er.fields) > 500 {
			return nil, errors.New("at most 500 fields")
		}
	}
	return er, nil
}

func attachment(w http.ResponseWriter, name, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"; filename*=UTF-8''"+url.PathEscape(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// safeFileName keeps letters, digits and a few separators.
func safeFileName(s string) string {
	b := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), ".")
}

func (s *Server) handleExportCollection(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.transferOff(w, r) {
		return
	}
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	ns := rbac.Namespace(db, coll)
	if !s.authorize(w, r, rc, rbac.Export, rbac.Create, ns) || !s.authorize(w, r, rc, rbac.Documents, rbac.Get, ns) {
		return
	}
	er, err := s.parseExport(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	fo := options.Find().SetLimit(er.limit).SetBatchSize(500)
	if len(er.spec.projection) > 0 {
		fo.SetProjection(er.spec.projection)
	}
	if len(er.spec.sort) > 0 {
		fo.SetSort(er.spec.sort)
	}
	start := time.Now()
	ctx := r.Context()
	cur, err := rc.sess.Client.Database(db).Collection(coll).Find(ctx, er.spec.filter, fo)
	if err != nil {
		s.mongoError(w, r, rc, "export", err)
		return
	}
	defer cur.Close(context.Background())

	name := safeFileName(db+"."+coll) + "." + er.format.Extension()
	ctype := er.format.ContentType()
	if er.gzip {
		name, ctype = name+".gz", "application/gzip"
	}
	attachment(w, name, ctype)
	longWrite(w)
	var out io.Writer = w
	var gz *gzip.Writer
	if er.gzip {
		gz = gzip.NewWriter(w)
		out = gz
	}
	enc, _ := transfer.NewEncoder(out, transfer.ExportOptions{Format: er.format, Canonical: er.canonical, Fields: er.fields})
	var n int64
	var werr error
	for cur.Next(ctx) {
		if werr = enc.Write(cur.Current); werr != nil {
			break
		}
		n++
	}
	if werr == nil {
		werr = enc.Close()
	}
	if gz != nil && werr == nil {
		werr = gz.Close()
	}
	outcome, reason := audit.Success, ""
	if err := errors.Join(cur.Err(), werr); err != nil {
		// Headers are sent: the client sees a truncated download.
		outcome, reason = audit.Failure, "export interrupted after "+strconv.FormatInt(n, 10)+" documents"
	}
	e := s.baseEvent(rc, "export", outcome, reason)
	e.Database, e.Collection, e.Target, e.Count, e.DurationMS = db, coll, string(er.format), n, time.Since(start).Milliseconds()
	s.Audit.Record(r.Context(), e)
	s.Metrics.TransferJobs.WithLabelValues("export", outcome).Inc()
	s.Metrics.TransferDocs.WithLabelValues("export").Add(float64(n))
}

// manifestEntry describes one file of a database export archive.
type manifestEntry struct {
	File       string `json:"file"`
	Collection string `json:"collection"`
	Documents  int64  `json:"documents"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	Complete   bool   `json:"complete"`
}

type countingWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

// handleExportDatabase streams a zip archive: one file per collection the
// user may export, its indexes and options, and a manifest with document
// counts and SHA-256 checksums (written last).
func (s *Server) handleExportDatabase(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.transferOff(w, r) {
		return
	}
	db := r.PathValue("db")
	if !query.ValidDatabaseName(db) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid database name")
		return
	}
	if !s.authorize(w, r, rc, rbac.Export, rbac.Create, db) {
		return
	}
	er, err := s.parseExport(r)
	if err != nil || (er.format != transfer.NDJSON && er.format != transfer.BSON && er.format != transfer.JSON) {
		writeError(w, r, http.StatusBadRequest, "invalid_query", "database exports support ndjson, json or bson without filters")
		return
	}
	ctx := r.Context()
	specs, err := rc.sess.Client.Database(db).ListCollectionSpecifications(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		s.mongoError(w, r, rc, "export", err)
		return
	}
	slices.SortFunc(specs, func(a, b mongo.CollectionSpecification) int { return strings.Compare(a.Name, b.Name) })
	start := time.Now()
	attachment(w, safeFileName(db)+"-export-"+start.UTC().Format("20060102T150405Z")+".zip", "application/zip")
	longWrite(w)
	zw := zip.NewWriter(w)
	var entries []manifestEntry
	var skipped []string
	var total int64
	failed := false
	for _, sp := range specs {
		ns := rbac.Namespace(db, sp.Name)
		if query.SystemCollection(sp.Name) || !s.allowed(rc, rbac.Export, rbac.Create, ns) || !s.allowed(rc, rbac.Documents, rbac.Get, ns) {
			skipped = append(skipped, sp.Name)
			continue
		}
		file := safeFileName(sp.Name) + "." + er.format.Extension()
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: file, Method: zip.Deflate, Modified: start})
		if err != nil {
			failed = true
			break
		}
		cw := &countingWriter{w: fw, h: sha256.New()}
		enc, _ := transfer.NewEncoder(cw, transfer.ExportOptions{Format: er.format, Canonical: er.canonical})
		me := manifestEntry{File: file, Collection: sp.Name}
		cur, err := rc.sess.Client.Database(db).Collection(sp.Name).Find(ctx, bson.D{}, options.Find().SetBatchSize(500).SetLimit(max(er.limit-total, 1)))
		if err == nil {
			for cur.Next(ctx) && total < er.limit {
				if enc.Write(cur.Current) != nil {
					break
				}
				me.Documents++
				total++
			}
			err = cur.Err()
			_ = cur.Close(context.Background())
		}
		closeErr := enc.Close()
		me.Bytes, me.SHA256, me.Complete = cw.n, hex.EncodeToString(cw.h.Sum(nil)), err == nil && closeErr == nil
		entries = append(entries, me)
		// Collection options and indexes, to recreate the collection.
		if mw, err := zw.CreateHeader(&zip.FileHeader{Name: safeFileName(sp.Name) + ".metadata.json", Method: zip.Deflate, Modified: start}); err == nil {
			var idx []bson.Raw
			if c, err := rc.sess.Client.Database(db).Collection(sp.Name).Indexes().List(ctx); err == nil {
				_ = c.All(ctx, &idx)
			}
			meta := bson.D{{Key: "collectionName", Value: sp.Name}, {Key: "options", Value: sp.Options}, {Key: "indexes", Value: idx}}
			if b, err := bson.MarshalExtJSON(meta, true, false); err == nil {
				_, _ = mw.Write(b)
			}
		}
		if ctx.Err() != nil {
			failed = true
			break
		}
	}
	manifest := map[string]any{
		"tool": "mongo-portal", "version": s.Build.Version, "createdAt": start.UTC(), "profile": rc.sess.Profile, "database": db,
		"exportedBy": rc.user(), "mongoUser": rc.sess.MongoUser + "@" + rc.sess.AuthSource, "format": er.format, "canonicalEJSON": er.canonical,
		"documents": total, "files": entries, "skippedCollections": skipped, "limitReached": total >= er.limit,
		"consistency": "Collections were read one after another without a snapshot; this is not a point-in-time backup.",
	}
	if mw, err := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: start}); err == nil {
		enc := json.NewEncoder(mw)
		enc.SetIndent("", "  ")
		_ = enc.Encode(manifest)
	}
	if err := zw.Close(); err != nil {
		failed = true
	}
	outcome := audit.Success
	if failed {
		outcome = audit.Failure
	}
	e := s.baseEvent(rc, "export_database", outcome, "")
	e.Database, e.Target, e.Count, e.DurationMS = db, string(er.format), total, time.Since(start).Milliseconds()
	s.Audit.Record(r.Context(), e)
	s.Metrics.TransferJobs.WithLabelValues("export_database", outcome).Inc()
	s.Metrics.TransferDocs.WithLabelValues("export").Add(float64(total))
}

// ---- import jobs ----

// Job states.
const (
	jobQueued    = "queued"
	jobRunning   = "running"
	jobSucceeded = "succeeded"
	jobFailed    = "failed"
	jobCancelled = "cancelled"
)

// JobView is the state of an import job as shown to its owner.
type JobView struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Profile    string    `json:"profile"`
	Database   string    `json:"database"`
	Collection string    `json:"collection"`
	Format     string    `json:"format"`
	Mode       string    `json:"mode"`
	DryRun     bool      `json:"dryRun"`
	FileName   string    `json:"fileName,omitempty"`
	FileBytes  int64     `json:"fileBytes"`
	SHA256     string    `json:"sha256"`
	Gzip       bool      `json:"gzip"`
	State      string    `json:"state"`
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	Read       int64     `json:"read"`
	Inserted   int64     `json:"inserted"`
	Upserted   int64     `json:"upserted"`
	Matched    int64     `json:"matched"`
	Failed     int64     `json:"failed"`
	Processed  int64     `json:"processedBytes"`
	Errors     []JobErr  `json:"errors"`
}

// Job is an import running in the background on this replica.
type Job struct {
	mu     sync.Mutex
	v      JobView
	owner  string
	cancel context.CancelFunc
}

// JobErr is one rejected record.
type JobErr struct {
	Record int64  `json:"record"`
	Code   int32  `json:"code,omitempty"`
	Msg    string `json:"message"`
}

func (j *Job) snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	c := j.v
	c.Errors = slices.Clone(j.v.Errors[:min(len(j.v.Errors), 20)])
	if c.Errors == nil {
		c.Errors = []JobErr{}
	}
	return c
}

type jobManager struct {
	mu   sync.Mutex
	jobs map[string]*Job
	sem  chan struct{}
}

func newJobManager(concurrent int) *jobManager {
	return &jobManager{jobs: map[string]*Job{}, sem: make(chan struct{}, max(concurrent, 1))}
}

func (m *jobManager) add(j *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.jobs {
		x.mu.Lock()
		busy := x.owner == j.owner && (x.v.State == jobQueued || x.v.State == jobRunning)
		x.mu.Unlock()
		if busy {
			return errors.New("you already have an import running; wait for it or cancel it")
		}
	}
	m.jobs[j.v.ID] = j
	return nil
}

func (m *jobManager) get(id, owner string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.jobs[id]; ok && j.owner == owner {
		return j
	}
	return nil
}

func (m *jobManager) list(owner string) []JobView {
	m.mu.Lock()
	var out []JobView
	for _, j := range m.jobs {
		if j.owner == owner {
			out = append(out, j.snapshot())
		}
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b JobView) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out
}

// RunJobs removes finished jobs after transfer.jobRetention and cancels
// running ones when ctx ends.
func (s *Server) RunJobs(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.jobs.mu.Lock()
			for _, j := range s.jobs.jobs {
				if j.cancel != nil {
					j.cancel()
				}
			}
			s.jobs.mu.Unlock()
			return
		case <-t.C:
			cutoff := time.Now().Add(-s.Config.Transfer.JobRetention)
			s.jobs.mu.Lock()
			for id, j := range s.jobs.jobs {
				j.mu.Lock()
				done := !j.v.FinishedAt.IsZero() && j.v.FinishedAt.Before(cutoff)
				j.mu.Unlock()
				if done {
					delete(s.jobs.jobs, id)
				}
			}
			s.jobs.mu.Unlock()
		}
	}
}

func importOptions(r *http.Request) (transfer.ImportOptions, string, error) {
	q := r.URL.Query()
	f, err := transfer.ParseFormat(q.Get("format"))
	if err != nil {
		return transfer.ImportOptions{}, "", err
	}
	o := transfer.ImportOptions{Format: f, KeepBlanks: q.Get("keepBlanks") == "true"}
	if m := q.Get("mapping"); m != "" {
		if len(m) > 64<<10 {
			return o, "", errors.New("mapping is too large")
		}
		if err := json.Unmarshal([]byte(m), &o.Mapping); err != nil {
			return o, "", errors.New("mapping must be a JSON array of {column, field, type, skip}")
		}
		if len(o.Mapping) > 1000 {
			return o, "", errors.New("at most 1000 mapped columns")
		}
	}
	mode := q.Get("mode")
	switch mode {
	case "", "insert":
		mode = "insert"
	case "upsert":
	default:
		return o, "", errors.New("mode must be insert or upsert")
	}
	return o, mode, o.Validate()
}

func (s *Server) handleImportPreview(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.transferOff(w, r) {
		return
	}
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Import, rbac.Create, rbac.Namespace(db, coll)) {
		return
	}
	o, _, err := importOptions(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	res, err := transfer.Preview(io.LimitReader(r.Body, previewBytes), o, 20)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "The file cannot be read as "+string(o.Format)+": "+truncate(err.Error(), 200))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleImport stores the upload in the temporary directory (with its
// SHA-256), then imports it in the background with the user's session.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.transferOff(w, r) {
		return
	}
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if query.SystemCollection(coll) {
		writeError(w, r, http.StatusForbidden, "system_collection", "Imports into system collections are not allowed")
		return
	}
	ns := rbac.Namespace(db, coll)
	o, mode, err := importOptions(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	if !s.authorize(w, r, rc, rbac.Import, rbac.Create, ns) || !s.authorize(w, r, rc, rbac.Documents, rbac.Create, ns) {
		return
	}
	if mode == "upsert" && !s.authorize(w, r, rc, rbac.Documents, rbac.Update, ns) {
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Minute))

	j := &Job{owner: rc.owner, v: JobView{ID: session.NewToken()[:20], Kind: "import", Profile: rc.sess.Profile, Database: db, Collection: coll,
		Format: string(o.Format), Mode: mode, DryRun: r.URL.Query().Get("dryRun") == "true", FileName: truncate(r.URL.Query().Get("fileName"), 200),
		State: jobQueued, CreatedAt: time.Now().UTC(), Errors: []JobErr{}}}
	if err := s.jobs.add(j); err != nil {
		writeError(w, r, http.StatusConflict, "job_running", err.Error())
		return
	}
	dir := s.Config.Transfer.TempDir
	f, err := os.CreateTemp(dir, "mongo-portal-import-*")
	if err != nil {
		s.finishJob(j, jobFailed, "temporary storage is not writable")
		writeError(w, r, http.StatusInsufficientStorage, "storage", "The portal cannot buffer the upload (transfer.tempDir)")
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		var mbe *http.MaxBytesError
		msg, status := "The upload was interrupted", http.StatusBadRequest
		if errors.As(err, &mbe) {
			msg, status = fmt.Sprintf("The file is larger than %d MiB (transfer.maxImportBytes)", s.Config.Transfer.MaxImportBytes>>20), http.StatusRequestEntityTooLarge
		}
		s.finishJob(j, jobFailed, msg)
		writeError(w, r, status, "upload_failed", msg)
		return
	}
	j.mu.Lock()
	j.v.FileBytes, j.v.SHA256 = n, hex.EncodeToString(h.Sum(nil))
	j.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	sess, event := rc.sess, s.baseEvent(rc, "import", "", "")
	event.Database, event.Collection = db, coll
	go s.runImport(ctx, j, sess, f.Name(), o, event)
	writeJSON(w, http.StatusAccepted, j.snapshot())
}

func (s *Server) finishJob(j *Job, state, msg string) {
	j.mu.Lock()
	j.v.State, j.v.FinishedAt = state, time.Now().UTC()
	if msg != "" {
		j.v.Message = msg
	}
	j.mu.Unlock()
}

func (s *Server) runImport(ctx context.Context, j *Job, sess *session.Session, path string, o transfer.ImportOptions, ev audit.Event) {
	defer os.Remove(path)
	select {
	case s.jobs.sem <- struct{}{}:
		defer func() { <-s.jobs.sem }()
	case <-ctx.Done():
		s.finishJob(j, jobCancelled, "cancelled before it started")
		return
	}
	start := time.Now()
	j.mu.Lock()
	j.v.State, j.v.StartedAt = jobRunning, start.UTC()
	j.mu.Unlock()
	state, msg := s.importFile(ctx, j, sess, path, o)
	s.finishJob(j, state, msg)
	snap := j.snapshot()
	outcome := audit.Success
	if state != jobSucceeded {
		outcome = audit.Failure
	}
	ev.Outcome, ev.Reason, ev.Count, ev.DurationMS = outcome, state+" "+msg, snap.Inserted+snap.Upserted, time.Since(start).Milliseconds()
	ev.Target = fmt.Sprintf("%s %s sha256:%s failed:%d", snap.Format, snap.Mode, snap.SHA256, snap.Failed)
	if snap.DryRun {
		ev.Action = "import_dry_run"
	}
	s.Audit.Record(context.Background(), ev)
	s.Metrics.TransferJobs.WithLabelValues("import", state).Inc()
	s.Metrics.TransferDocs.WithLabelValues("import").Add(float64(snap.Inserted + snap.Upserted))
}

type progressReader struct {
	r io.Reader
	j *Job
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.j.mu.Lock()
	p.j.v.Processed += int64(n)
	p.j.mu.Unlock()
	return n, err
}

func (s *Server) importFile(ctx context.Context, j *Job, sess *session.Session, path string, o transfer.ImportOptions) (string, string) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return jobFailed, "the buffered upload is missing"
	}
	defer f.Close()
	in, gz, err := transfer.Decompress(&progressReader{r: f, j: j})
	if err != nil {
		return jobFailed, err.Error()
	}
	j.mu.Lock()
	j.v.Gzip = gz
	j.mu.Unlock()
	dec, err := transfer.NewDecoder(in, o)
	if err != nil {
		return jobFailed, err.Error()
	}
	c := sess.Client.Database(j.v.Database).Collection(j.v.Collection)
	batch := make([]bson.D, 0, s.Config.Transfer.BatchSize)
	records := make([]int64, 0, s.Config.Transfer.BatchSize)
	maxErr := s.Config.Transfer.MaxErrors
	addErr := func(rec int64, code int32, msg string) bool {
		j.mu.Lock()
		defer j.mu.Unlock()
		j.v.Failed++
		if len(j.v.Errors) < 1000 {
			j.v.Errors = append(j.v.Errors, JobErr{Record: rec, Code: code, Msg: truncate(msg, 300)})
		}
		return j.v.Failed < int64(maxErr)
	}
	flush := func() bool {
		if len(batch) == 0 || j.v.DryRun {
			batch, records = batch[:0], records[:0]
			return true
		}
		ok := s.writeBatch(ctx, c, j, batch, records, addErr)
		batch, records = batch[:0], records[:0]
		return ok
	}
	for n := 0; ; n++ {
		if ctx.Err() != nil || (n%500 == 0 && sessionGone(s, sess)) {
			return jobCancelled, "cancelled (or the MongoDB session ended)"
		}
		doc, err := dec.Next()
		var re *transfer.RecordError
		switch {
		case errors.Is(err, io.EOF):
			if !flush() {
				return jobFailed, fmt.Sprintf("stopped after %d rejected documents (transfer.maxErrors)", maxErr)
			}
			if ctx.Err() != nil {
				return jobCancelled, "cancelled"
			}
			return jobSucceeded, ""
		case errors.As(err, &re):
			j.mu.Lock()
			j.v.Read++
			j.mu.Unlock()
			if !addErr(re.Record, 0, re.Msg) {
				return jobFailed, fmt.Sprintf("stopped after %d rejected documents (transfer.maxErrors)", maxErr)
			}
			continue
		case err != nil:
			flush()
			return jobFailed, "the file cannot be read: " + truncate(err.Error(), 200)
		}
		j.mu.Lock()
		j.v.Read++
		j.mu.Unlock()
		if j.v.Mode == "upsert" && !hasID(doc) {
			if !addErr(dec.Record(), 0, "upsert needs an _id field") {
				return jobFailed, fmt.Sprintf("stopped after %d rejected documents (transfer.maxErrors)", maxErr)
			}
			continue
		}
		batch, records = append(batch, doc), append(records, dec.Record())
		if len(batch) == cap(batch) && !flush() {
			return jobFailed, fmt.Sprintf("stopped after %d rejected documents (transfer.maxErrors)", maxErr)
		}
	}
}

func hasID(d bson.D) bool {
	return slices.ContainsFunc(d, func(e bson.E) bool { return e.Key == "_id" })
}

func sessionGone(s *Server, sess *session.Session) bool {
	return !slices.ContainsFunc(s.Store.All(), func(x *session.Session) bool { return x == sess })
}

// writeBatch inserts (or upserts) one batch, unordered, recording rejected
// documents with their input record numbers. It returns false when the
// import must stop (too many errors or a fatal error).
func (s *Server) writeBatch(ctx context.Context, c *mongo.Collection, j *Job, batch []bson.D, records []int64, addErr func(int64, int32, string) bool) bool {
	octx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var err error
	if j.v.Mode == "upsert" {
		models := make([]mongo.WriteModel, len(batch))
		for i, d := range batch {
			id := d[slices.IndexFunc(d, func(e bson.E) bool { return e.Key == "_id" })].Value
			models[i] = mongo.NewReplaceOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}).SetReplacement(d).SetUpsert(true)
		}
		var res *mongo.BulkWriteResult
		res, err = c.BulkWrite(octx, models, options.BulkWrite().SetOrdered(false))
		if res != nil {
			j.mu.Lock()
			j.v.Upserted += res.UpsertedCount
			j.v.Matched += res.MatchedCount
			j.mu.Unlock()
		}
	} else {
		docs := make([]any, len(batch))
		for i := range batch {
			docs[i] = batch[i]
		}
		var res *mongo.InsertManyResult
		res, err = c.InsertMany(octx, docs, options.InsertMany().SetOrdered(false))
		if res != nil {
			j.mu.Lock()
			j.v.Inserted += int64(len(res.InsertedIDs))
			j.mu.Unlock()
		}
	}
	if err == nil {
		return true
	}
	var bwe mongo.BulkWriteException
	if errors.As(err, &bwe) && bwe.WriteConcernError == nil {
		cont := true
		for _, we := range bwe.WriteErrors {
			rec := int64(0)
			if we.Index >= 0 && we.Index < len(records) {
				rec = records[we.Index]
			}
			if !addErr(rec, int32(we.Code), mongoconn.Classify(we).Msg+" ("+truncate(we.Message, 200)+")") { // #nosec G115 -- MongoDB error codes fit int32
				cont = false
			}
		}
		if j.v.Mode != "upsert" {
			j.mu.Lock()
			j.v.Inserted += int64(len(batch) - len(bwe.WriteErrors))
			j.mu.Unlock()
		}
		return cont
	}
	me := mongoconn.Classify(err)
	addErr(records[0], me.Code, "batch failed: "+me.Msg)
	j.mu.Lock()
	j.v.Message = me.Msg
	j.mu.Unlock()
	return false
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	jobs := s.jobs.list(rc.owner)
	if jobs == nil {
		jobs = []JobView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs, "note": "Jobs run on the portal replica that received the upload."})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	j := s.jobs.get(r.PathValue("id"), rc.owner)
	if j == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Job not found")
		return
	}
	writeJSON(w, http.StatusOK, j.snapshot())
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	j := s.jobs.get(r.PathValue("id"), rc.owner)
	if j == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Job not found")
		return
	}
	if j.cancel != nil {
		j.cancel()
	}
	s.auditEvent(r, rc, "import_cancel", audit.Success, j.v.ID)
	writeJSON(w, http.StatusOK, j.snapshot())
}

// handleJobErrors downloads the rejected records of an import as NDJSON.
func (s *Server) handleJobErrors(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	j := s.jobs.get(r.PathValue("id"), rc.owner)
	if j == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Job not found")
		return
	}
	j.mu.Lock()
	errs := slices.Clone(j.v.Errors)
	j.mu.Unlock()
	attachment(w, "import-"+j.v.ID+"-errors.ndjson", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, e := range errs {
		_ = enc.Encode(e)
	}
}
