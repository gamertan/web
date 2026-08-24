// SPDX-License-Identifier: MPL-2.0

package requestlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// JSONL is a synchronous append-only sink. The caller owns rotation.
type JSONL struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	err    error
}

// JSONLOptions controls the local file boundary. A zero FileMode preserves the
// private 0600 default. Mode 0640 may be used when the deployment has assigned
// the file to one explicit collector group; world-readable or writable modes
// are never accepted.
type JSONLOptions struct {
	FileMode fs.FileMode
}

func OpenJSONL(path string) (*JSONL, error) {
	return OpenJSONLWithOptions(path, JSONLOptions{})
}

func OpenJSONLWithOptions(path string, options JSONLOptions) (*JSONL, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("requestlog: JSONL path must be clean and absolute")
	}
	mode := options.FileMode
	if mode == 0 {
		mode = 0o600
	}
	if mode != 0o600 && mode != 0o640 {
		return nil, errors.New("requestlog: JSONL mode must be 0600 or 0640")
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("requestlog: JSONL destination must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return nil, err
	}
	if err = file.Chmod(mode); err != nil {
		file.Close()
		return nil, err
	}
	return &JSONL{file: file, writer: bufio.NewWriterSize(file, 64*1024)}, nil
}

func (sink *JSONL) WriteRecord(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	if _, err = sink.writer.Write(append(body, '\n')); err == nil {
		err = sink.writer.Flush()
	}
	if err != nil {
		sink.err = err
	}
	return err
}

func (sink *JSONL) Err() error { sink.mu.Lock(); defer sink.mu.Unlock(); return sink.err }

func (sink *JSONL) Close() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.file == nil {
		return sink.err
	}
	flushErr := sink.writer.Flush()
	closeErr := sink.file.Close()
	sink.file = nil
	return errors.Join(sink.err, flushErr, closeErr)
}
