package har

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Load reads a HAR file: a har2mcp recording or a plain HAR such as a Chrome
// DevTools export. Unknown fields are ignored and a leading UTF-8 byte order
// mark is skipped.
func Load(path string) (*HAR, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var probe struct {
		Log json.RawMessage `json:"log"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("%s: not a HAR file: %w", path, err)
	}
	if len(probe.Log) == 0 || string(probe.Log) == "null" {
		return nil, fmt.Errorf("%s: not a HAR file: no \"log\" object", path)
	}
	var h HAR
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("%s: invalid HAR: %w", path, err)
	}
	return &h, nil
}

// Save writes h to path as JSON indented with two spaces. The file is created
// with mode 0600, and an existing file is replaced, so it ends up 0600 too:
// recordings hold passwords and session cookies.
func Save(path string, h *HAR) error {
	if h == nil {
		return errors.New("har: Save of a nil HAR")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(h); err != nil {
		return fmt.Errorf("har: encode: %w", err)
	}
	return writeFileAtomic(path, buf.Bytes(), 0o600)
}

// writeFileAtomic writes data to a temporary file next to path (created 0600
// by os.CreateTemp), sets perm, and renames it over path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
