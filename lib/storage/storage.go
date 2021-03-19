package storage

import "context"

// Storage is an interface for an internally synchronized key-value storage
// system that a server can use to store data.
type Storage interface {
	// Get returns the value associated with a certain key.
	Get(ctx context.Context, key []byte) ([]byte, error)

	// Put maps a key to a value, creating a new mapping if the key is not
	// already mapped.
	Put(ctx context.Context, key []byte, value []byte) error

	// Closes the database.
	Close(ctx context.Context) error
}

// AppendableStorage is an interface for special storage systems that allow
// data to be atomically appended to a value.
type AppendableStorage interface {
	Storage
	Append(ctx context.Context, key string, data []byte) error
}
