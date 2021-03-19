package storage

import (
	"context"
	"sync"
)

// MapStorage is a toy storage system. All data is stored in memory via a
// single golang map that is trivially synchronized.
type MapStorage struct {
	data map[string][]byte
	lock sync.RWMutex
}

// NewMapStorage instantiates MapStorage.
func NewMapStorage() *MapStorage {
	return &MapStorage{
		data: make(map[string][]byte),
	}
}

// GetData is useful for debugging
func (ms *MapStorage) GetData() map[string][]byte {
	return ms.data
}

// Get retrieves the key in the underlying map.
func (ms *MapStorage) Get(ctx context.Context, key []byte) ([]byte, error) {
	ms.lock.RLock()
	defer ms.lock.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, _ := ms.data[string(key)]
	return value, nil
}

// Put stores the key-value pair in the underlying map.
func (ms *MapStorage) Put(ctx context.Context, key []byte, value []byte) error {
	ms.lock.Lock()
	defer ms.lock.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	ms.data[string(key)] = value
	return nil
}

func (ms *MapStorage) Close(ctx context.Context) error {
	ms.data = nil
	return nil
}

// Append atomically appends data to the specified key-value pair.
func (ms *MapStorage) Append(ctx context.Context, key string, value []byte) error {
	ms.lock.Lock()
	defer ms.lock.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	ms.data[key] = append(ms.data[key], value...)
	return nil
}
