package storage

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func storageGetPutTest(ctx context.Context, t *testing.T, storage Storage) {
	originalData := []byte("world")
	key := []byte("hello")
	storage.Put(ctx, key, originalData)
	recoveredData, _ := storage.Get(ctx, key)

	if !reflect.DeepEqual(originalData, recoveredData) {
		t.Error("Cannot get stored data")
	}
}

func TestMapGetPut(t *testing.T) {
	ctx := context.Background()
	storageGetPutTest(ctx, t, NewMapStorage())
}

func TestLeveldbkvGetPut(t *testing.T) {
	ctx := context.Background()
	//dir, err := ioutil.TempDir("", "teststore")
	//if err != nil {
	//	panic(err)
	//}
	//defer os.RemoveAll(dir)
	db := OpenFile("teststore")
	defer db.Close(ctx)
	storageGetPutTest(ctx, t, db)

	err := os.RemoveAll("./teststore/")
	if err != nil {
		t.Error(err)
	}
}
