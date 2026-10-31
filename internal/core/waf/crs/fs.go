package crs

import (
	"embed"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

//go:embed crs-setup.conf rules/*.conf rules/*.data
var rulesFS embed.FS

// overlayFS exposes the embedded CRS plus imported pack files under paths of
// the form packs/<packID>/<relative path>.
type overlayFS struct {
	base  fs.FS
	files map[string]string
}

func (o overlayFS) Open(name string) (fs.File, error) {
	if content, ok := o.files[name]; ok {
		return &memFile{name: path.Base(name), data: []byte(content)}, nil
	}
	if o.base == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return o.base.Open(name)
}

type memFile struct {
	name   string
	data   []byte
	offset int64
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: f.name, size: int64(len(f.data))}, nil
}

func (f *memFile) Read(p []byte) (int, error) {
	if f.offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *memFile) Close() error { return nil }

type memFileInfo struct {
	name string
	size int64
}

func (i memFileInfo) Name() string       { return i.name }
func (i memFileInfo) Size() int64        { return i.size }
func (i memFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i memFileInfo) ModTime() time.Time { return time.Time{} }
func (i memFileInfo) IsDir() bool        { return false }
func (i memFileInfo) Sys() any           { return nil }

// safePackID keeps include paths predictable and contained.
func safePackID(id string) string {
	id = strings.TrimSpace(id)
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "pack"
	}
	return b.String()
}

func buildOverlayFS(conf Config) overlayFS {
	files := make(map[string]string)
	for _, pack := range conf.Packs {
		prefix := "packs/" + safePackID(pack.ID) + "/"
		for name, content := range pack.Files {
			clean := path.Clean("/" + strings.TrimSpace(name))
			clean = strings.TrimPrefix(clean, "/")
			if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
				continue
			}
			files[prefix+clean] = content
		}
	}
	return overlayFS{base: rulesFS, files: files}
}
