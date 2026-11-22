package analyze

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// detectFile marks uploads (multipart requests with a file part) and
// downloads (attachments and binary responses).
func detectFile(op *operation) *spec.FileOp {
	parts := map[string]int{}
	var order []string
	for _, s := range op.samples {
		for _, f := range s.req.files {
			if parts[f.name] == 0 {
				order = append(order, f.name)
			}
			parts[f.name]++
		}
	}
	if len(order) > 0 {
		best := order[0]
		for _, p := range order {
			if parts[p] > parts[best] {
				best = p
			}
		}
		return &spec.FileOp{Direction: "upload", Part: best}
	}
	for _, s := range op.samples {
		if isBinaryDownload(s.e) {
			return &spec.FileOp{Direction: "download"}
		}
	}
	return nil
}

// Field names (lower case, without _ and -) used by chunked and resumable
// upload protocols, including resumable.js, Dropzone and flow.js.
var (
	chunkOffsetNames = []string{"offset", "start", "chunkoffset", "byteoffset", "pos", "position", "dzchunkbyteoffset", "resumablecurrentchunkoffset"}
	chunkIndexNames  = []string{"chunkindex", "chunk", "chunknumber", "chunkno", "index", "part", "partnumber", "partindex", "partno", "resumablechunknumber", "dzchunkindex", "flowchunknumber"}
	chunkTotalNames  = []string{"total", "totalsize", "filesize", "size", "totalbytes", "fullsize", "resumabletotalsize", "dztotalfilesize", "flowtotalsize"}
	chunkCountNames  = []string{"totalchunks", "chunks", "chunkcount", "numchunks", "resumabletotalchunks", "dztotalchunkcount", "flowtotalchunks", "totalparts", "partcount"}
)

func normName(s string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(s))
}

func nameIn(s string, list []string) bool {
	n := normName(s)
	for _, l := range list {
		if n == l {
			return true
		}
	}
	return false
}

type chunkResult struct {
	chunking *spec.Chunking
	fields   map[string]bool // body fields the generated server fills per chunk
	notes    []string
}

// detectChunking recognizes a chunked upload: several requests to the same
// endpoint whose offset (or chunk index) grows by a fixed chunk size. Only
// a consistent pattern is modeled; anything else that looks chunked is
// flagged for review rather than guessed.
func detectChunking(op *operation, part string) chunkResult {
	var res chunkResult
	stats := collectFields(op)
	n := len(op.samples)

	ints := func(fs *fieldStat) ([]int64, bool) {
		if fs.loc != "body" || len(fs.vals) != n {
			return nil, false
		}
		out := make([]int64, n)
		for i, v := range fs.vals {
			switch x := v.(type) {
			case int64:
				out[i] = x
			case string:
				iv, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
				if err != nil {
					return nil, false
				}
				out[i] = iv
			default:
				return nil, false
			}
		}
		return out, true
	}
	find := func(names []string) (*fieldStat, []int64) {
		for _, fs := range stats {
			if nameIn(lastSegment(fs.path), names) {
				if vals, ok := ints(fs); ok {
					return fs, vals
				}
			}
		}
		return nil, nil
	}

	offF, offs := find(chunkOffsetNames)
	idxF, idxs := find(chunkIndexNames)
	totF, tots := find(chunkTotalNames)
	var countF *fieldStat
	for _, fs := range stats {
		if nameIn(lastSegment(fs.path), chunkCountNames) {
			countF = fs
		}
	}

	if n < 2 {
		if offF != nil || idxF != nil {
			f := offF
			if f == nil {
				f = idxF
			}
			res.notes = append(res.notes, fmt.Sprintf("this upload has a chunk field (%q) but only one request was recorded, so the chunk size is unknown; record a larger file or set file.chunked by hand", f.path))
		}
		return res
	}

	// The file part's size in each sample, -1 when unknown.
	sizes := make([]int64, n)
	names := map[string]bool{}
	for i, s := range op.samples {
		sizes[i] = -1
		for _, f := range s.req.files {
			if f.name == part {
				sizes[i] = f.size
				names[f.fileName] = true
			}
		}
	}

	looksChunked := offF != nil || idxF != nil
	if !looksChunked && len(names) == 1 {
		for _, fs := range stats {
			if vals, ok := ints(fs); ok && distinctCount(fs.vals) > 1 && len(vals) == n {
				looksChunked = true
			}
		}
	}
	if !looksChunked {
		return res
	}
	unrecognized := func(why string) chunkResult {
		res.notes = append(res.notes, fmt.Sprintf("this upload looks chunked (%d requests for one file) but the chunk pattern was not recognized (%s); check file.chunked and the request fields", n, why))
		return res
	}
	if offF == nil && idxF == nil {
		return unrecognized("no offset or chunk index field")
	}

	// Put the samples in upload order.
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	key := offs
	if key == nil {
		key = idxs
	}
	sort.SliceStable(order, func(a, b int) bool { return key[order[a]] < key[order[b]] })

	size := sizes[order[0]]
	if size <= 0 && offF != nil {
		size = offs[order[1]] - offs[order[0]]
	}
	if size <= 0 {
		return unrecognized("the chunk size is unknown")
	}
	for k, i := range order {
		if offF != nil && offs[i] != int64(k)*size {
			return unrecognized(fmt.Sprintf("%s %d is not a multiple of the %d-byte chunk size", offF.path, offs[i], size))
		}
		if idxF != nil && idxs[i] != idxs[order[0]]+int64(k) {
			return unrecognized(fmt.Sprintf("%s does not count up by one", idxF.path))
		}
		if idxF != nil && k == 0 && idxs[i] != 0 && idxs[i] != 1 {
			return unrecognized(fmt.Sprintf("%s starts at %d", idxF.path, idxs[i]))
		}
		if s := sizes[i]; s >= 0 && (s > size || (s < size && k != n-1)) {
			return unrecognized("the chunks are not all the same size")
		}
	}
	if totF != nil {
		last := order[n-1]
		if distinctCount(totF.vals) != 1 {
			return unrecognized(fmt.Sprintf("%s changes between chunks", totF.path))
		}
		if offF != nil && sizes[last] > 0 && tots[last] < offs[last]+sizes[last] {
			return unrecognized(fmt.Sprintf("%s is smaller than the data sent", totF.path))
		}
	}

	c := &spec.Chunking{ChunkSize: size}
	res.fields = map[string]bool{}
	if offF != nil {
		c.OffsetField = offF.path
		res.fields[offF.path] = true
	}
	if idxF != nil {
		c.IndexField = idxF.path
		res.fields[idxF.path] = true
	}
	if totF != nil {
		c.TotalField = totF.path
		res.fields[totF.path] = true
	}
	if countF != nil {
		res.notes = append(res.notes, fmt.Sprintf("body field %q looks like a chunk count, which har2mcp does not fill per file; check it", countF.path))
	}
	res.chunking = c
	return res
}
