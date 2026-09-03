// SPDX-License-Identifier: MPL-2.0

// Package medialocal stores prepared media in a private content-addressed
// filesystem tree.
package medialocal

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gamertan.com/web/media"
)

type Store struct {
	root string
	now  func() time.Time
}

type Options struct {
	Now func() time.Time
}

func Open(root string, options Options) (*Store, error) {
	absolute, err := filepath.Abs(root)
	if err != nil || filepath.Clean(absolute) != absolute {
		return nil, errors.New("medialocal: root must be a clean absolute path")
	}
	if err = secureDirectory(absolute, true); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("medialocal: resolve root: %w", err)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Store{root: resolved, now: options.Now}, nil
}

func (store *Store) Put(ctx context.Context, prepared media.Prepared) (media.Object, error) {
	if err := ctx.Err(); err != nil {
		return media.Object{}, err
	}
	if len(prepared.Data) == 0 || !media.ValidKey(prepared.Key()) || sha256.Sum256(prepared.Data) != prepared.Digest {
		return media.Object{}, media.ErrInvalidMedia
	}
	shard, target := store.objectPath(prepared.Key())
	if err := secureDirectory(shard, true); err != nil {
		return media.Object{}, err
	}
	if object, ok, err := inspect(target, prepared.MediaType); err != nil {
		return media.Object{}, err
	} else if ok {
		if object.Size != int64(len(prepared.Data)) {
			return media.Object{}, errors.New("medialocal: existing digest has an unexpected size")
		}
		return object, nil
	}
	temporary, err := os.CreateTemp(shard, ".upload-*")
	if err != nil {
		return media.Object{}, fmt.Errorf("medialocal: create temporary object: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0o640); err == nil {
		_, err = temporary.Write(prepared.Data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return media.Object{}, fmt.Errorf("medialocal: write object: %w", err)
	}
	if err = os.Link(temporaryName, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			object, ok, inspectErr := inspect(target, prepared.MediaType)
			if inspectErr != nil {
				return media.Object{}, inspectErr
			}
			if ok && object.Size == int64(len(prepared.Data)) {
				return object, nil
			}
		}
		return media.Object{}, fmt.Errorf("medialocal: commit object: %w", err)
	}
	return media.Object{Key: prepared.Key(), Size: int64(len(prepared.Data)), MediaType: prepared.MediaType, CreatedAt: store.now().UTC()}, nil
}

func (store *Store) Open(ctx context.Context, key string) (io.ReadCloser, media.Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, media.Object{}, err
	}
	if !media.ValidKey(key) {
		return nil, media.Object{}, media.ErrNotFound
	}
	shard, target := store.objectPath(key)
	if err := secureDirectory(shard, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, media.Object{}, media.ErrNotFound
		}
		return nil, media.Object{}, err
	}
	before, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, media.Object{}, media.ErrNotFound
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, media.Object{}, errors.New("medialocal: object is not a regular file")
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, media.Object{}, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, media.Object{}, errors.New("medialocal: object changed while opening")
	}
	return file, media.Object{Key: key, Size: after.Size(), CreatedAt: after.ModTime().UTC()}, nil
}

func (store *Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !media.ValidKey(key) {
		return media.ErrNotFound
	}
	_, target := store.objectPath(key)
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return media.ErrNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("medialocal: refusing to delete a non-regular object")
	}
	if err = os.Remove(target); errors.Is(err, os.ErrNotExist) {
		return media.ErrNotFound
	}
	return err
}

func (store *Store) objectPath(key string) (string, string) {
	shard := filepath.Join(store.root, key[:2])
	return shard, filepath.Join(shard, key)
}

func secureDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = os.MkdirAll(path, 0o750); err != nil {
			return fmt.Errorf("medialocal: create directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("medialocal: storage directory must not be a symlink")
	}
	return nil
}

func inspect(path, mediaType string) (media.Object, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return media.Object{}, false, nil
	}
	if err != nil {
		return media.Object{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return media.Object{}, false, errors.New("medialocal: existing object is not a regular file")
	}
	return media.Object{Key: filepath.Base(path), Size: info.Size(), MediaType: mediaType, CreatedAt: info.ModTime().UTC()}, true, nil
}
