// SPDX-License-Identifier: MPL-2.0

package requestlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

func OpenJSONL(path string) (*JSONL, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("requestlog: JSONL path must be clean and absolute")
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("requestlog: JSONL destination must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err = file.Chmod(0o600); err != nil {
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
