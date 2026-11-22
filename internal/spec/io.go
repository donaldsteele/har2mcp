package spec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

const fileHeader = `# har2mcp spec. Edit freely: rerunning 'har2mcp analyze' keeps your changes to
# tool names, descriptions, enabled, kind and inputs, and to the auth block.
# Format: https://github.com/donaldsteele/har2mcp/blob/main/docs/spec-format.md
`

// Load reads a spec file and validates it. Unknown keys are errors, so a
// typo in a hand edit is reported instead of silently ignored.
func Load(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file, not a har2mcp spec", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case s.Har2mcp == 0:
		return nil, fmt.Errorf("%s: not a har2mcp spec (no 'har2mcp: %d' line)", path, FormatVersion)
	case s.Har2mcp > FormatVersion:
		return nil, fmt.Errorf("%s: spec format %d is newer than this har2mcp supports (%d); upgrade har2mcp", path, s.Har2mcp, FormatVersion)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: invalid spec:\n%w", path, err)
	}
	return &s, nil
}

// Save writes s as YAML with mode 0644. Struct fields keep their declaration
// order and map keys are sorted, so saving the same spec twice gives the same
// bytes.
func Save(path string, s *Spec) error {
	if s == nil {
		return errors.New("spec: Save of a nil spec")
	}
	out := *s
	if out.Har2mcp == 0 {
		out.Har2mcp = FormatVersion
	}
	var buf bytes.Buffer
	buf.WriteString(fileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&out); err != nil {
		return fmt.Errorf("spec: encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("spec: encode: %w", err)
	}
	return writeFileAtomic(path, buf.Bytes(), 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
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
