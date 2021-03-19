package storage

import (
	"context"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type leveldbkv leveldb.DB

// OpenFile initializes a storage at provided path.
func OpenFile(path string) Storage {
	// open db & keep it open
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		panic(err)
	}
	return Wrap(db)
}

// Wrap takes in a leveldb and turns it into a storage.
func Wrap(db *leveldb.DB) Storage {
	return (*leveldbkv)(db)
}

func (db *leveldbkv) Get(ctx context.Context, key []byte) ([]byte, error) {
	return (*leveldb.DB)(db).Get(key, nil)
}

func (db *leveldbkv) Put(ctx context.Context, key, value []byte) error {
	return (*leveldb.DB)(db).Put(key, value, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) Close(ctx context.Context) error {
	return (*leveldb.DB)(db).Close()
}
