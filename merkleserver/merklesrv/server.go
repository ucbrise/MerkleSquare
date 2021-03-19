// Package merklesrv contains implementations for merkle server API.
package merklesrv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ucbrise/MerkleSquare/constants"
	"github.com/ucbrise/MerkleSquare/core"
	"github.com/ucbrise/MerkleSquare/lib/storage"

	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/immesys/bw2/crypto"
)

const MerkleDepth = constants.MerkleDepth

type ExtensionProofKey [2]uint64

type Server struct {
	Storage      storage.Storage
	MerkleSquare *core.MerkleSquare
	vrfPrivKey   vrf.PrivateKey

	LastPos     uint64
	LastPosLock *sync.RWMutex

	PublishedPos    uint64
	PublishedDigest *core.Digest
	epoch           uint64
	epochLock       *sync.RWMutex

	appendLock *sync.Mutex

	extensionProofCache  map[ExtensionProofKey][]byte
	CacheExtensionProofs bool

	epochDuration time.Duration
	stopper       chan struct{}
}

type KeyRecord struct {
	Position  uint64
	Signature []byte
	Key       []byte
}

func NewServer(storage storage.Storage, epochDuration time.Duration) *Server {
	privKey, err := vrf.GenerateKey(nil)
	if err != nil {
		return nil
	}
	server := &Server{
		Storage:              storage,
		MerkleSquare:         core.NewMerkleSquare(MerkleDepth),
		vrfPrivKey:           privKey,
		LastPos:              0,
		LastPosLock:          &sync.RWMutex{},
		PublishedPos:         0,
		epoch:                0,
		epochLock:            &sync.RWMutex{},
		appendLock:           &sync.Mutex{},
		epochDuration:        epochDuration,
		extensionProofCache:  make(map[ExtensionProofKey][]byte),
		CacheExtensionProofs: true,
		stopper:              make(chan struct{}),
	}
	server.PublishedDigest = server.MerkleSquare.GetDigest()

	if epochDuration != 0 {
		go server.EpochLoop(time.Unix(0, time.Now().Add(epochDuration).UnixNano()))
	}
	return server
}

func (s *Server) GetEpoch() uint64 {
	return s.epoch
}

func (s *Server) SetEpochDuration(newDuration time.Duration) {
	s.epochDuration = newDuration
}

func (s *Server) EpochLoop(firstEpochCommitTime time.Time) {
	firstEpochDuration := firstEpochCommitTime.Sub(time.Now())
	firstEpochTimer := time.NewTimer(firstEpochDuration)
	var epochTicker *time.Ticker
	until := firstEpochTimer.C
epochLoop:
	for {
		select {
		case <-until:
			fmt.Println("Start Commit!", time.Now())
			if firstEpochTimer != nil {
				firstEpochTimer.Stop()
				firstEpochTimer = nil
				epochTicker = time.NewTicker(s.epochDuration)
				until = epochTicker.C
			}
			s.IncrementEpoch()

		case <-s.stopper:
			fmt.Println("Stopping epoch loop!")
			break epochLoop
		}
	}
	if firstEpochTimer != nil {
		firstEpochTimer.Stop()
	}
	if epochTicker != nil {
		epochTicker.Stop()
	}
}

func (s *Server) IncrementEpoch() {
	s.epochLock.Lock()
	s.LastPosLock.RLock()

	// fmt.Println(s.PublishedPos)
	s.epoch++

	if s.PublishedPos == s.LastPos {
		s.LastPosLock.RUnlock()
		s.epochLock.Unlock()
		return
	}
	s.PublishedPos = s.LastPos

	s.LastPosLock.RUnlock()
	s.PublishedDigest = s.MerkleSquare.GetOldDigest(uint32(s.PublishedPos))
	s.epochLock.Unlock()
	//Dump obsolete extension proofs.
	s.extensionProofCache = make(map[ExtensionProofKey][]byte)
}

// Retreives user key from a key-value store on the server.
// Does not return any proof associated with the key. This is a simple query op.
func (s *Server) GetUserKey(ctx context.Context, user []byte,
	masterKey bool, position uint64) ([]byte, []byte, uint64, error) {
	var key KeyRecord
	var keyList []KeyRecord
	queryString := user
	if masterKey {
		queryString = append(queryString, []byte("MK")...)
	} else {
		queryString = append(queryString, []byte("PK")...)
	}

	serializedKey, err := s.Storage.Get(ctx, queryString)

	if err != nil {
		return nil, nil, 0, err
	}

	if serializedKey == nil {
		return nil, nil, 0, errors.New("no user key found")
	}

	s.epochLock.RLock()
	PublishedPos := s.PublishedPos
	s.epochLock.RUnlock()

	if masterKey {
		json.Unmarshal(serializedKey, &key)
	} else {
		json.Unmarshal(serializedKey, &keyList)
		// grab the latest key before provided position
		found := false
		for _, keyIter := range keyList {
			if keyIter.Position <= position && keyIter.Position <= PublishedPos {
				key = keyIter
				found = true
				break
			}
		}
		if !found || key.Position > position || key.Position > PublishedPos {
			// fmt.Println(key.Position)
			// fmt.Println(position)
			// fmt.Println(PublishedPos)
			return nil, nil, 0, errors.New("no key before requested position found")
		}
	}
	return key.Key, key.Signature, key.Position, nil
}

// Stores user key to a key-value store on the server.
func (s *Server) RegisterUserKey(ctx context.Context, user []byte,
	key []byte, signature []byte, verify bool) (uint64, error) {
	queryString := append(user, []byte("MK")...)
	if verify {
		//verify the user is not registered already
		mk_serialized, _ := s.Storage.Get(ctx, queryString)
		if mk_serialized != nil {
			return 0, errors.New("User is already registered")
		}

		//verify self-signed masterkey
		if !crypto.VerifyBlob(key, signature, key) {
			return 0, errors.New("Verification failed")
		}
	}

	// Assign a position to the new entry
	s.LastPosLock.Lock()
	s.appendLock.Lock()
	position := s.LastPos
	s.LastPos++
	s.MerkleSquare.Append(s.vrfPrivKey.Compute(user), key, signature)
	s.appendLock.Unlock()
	s.LastPosLock.Unlock()

	serializedKey, _ := json.Marshal(
		KeyRecord{
			Position:  position,
			Signature: signature,
			Key:       key,
		})
	s.Storage.Put(ctx, queryString, serializedKey)
	return position, nil
}

//USED FOR TESTING ONLY.
func (s *Server) AppendUserKey(ctx context.Context, user []byte,
	key []byte, privkey []byte) (uint64, error) {
	queryString := append(user, []byte("PK")...)
	s.LastPosLock.Lock()
	s.appendLock.Lock()
	position := s.LastPos
	s.LastPos++
	signature := make([]byte, 64)
	crypto.SignBlob(privkey, key, signature,
		append(key, []byte(strconv.Itoa(int(position)))...))
	//Add to merkle tree
	s.MerkleSquare.Append(s.vrfPrivKey.Compute(user), key, signature)
	s.appendLock.Unlock()
	s.LastPosLock.Unlock()

	//4. Add to K-V store
	var serializedKey []byte
	// Prepend to existing entry
	original, _ := s.Storage.Get(ctx, queryString)
	keyrecord := make([]KeyRecord, 1)
	keyrecord[0] = KeyRecord{Position: position, Signature: signature, Key: key}
	if original == nil {
		serializedKey, _ = json.Marshal(keyrecord)
	} else {
		var deserialized []KeyRecord
		json.Unmarshal(original, &deserialized)
		serializedKey, _ = json.Marshal(append(keyrecord, deserialized...))
	}
	s.Storage.Put(ctx, queryString, serializedKey)
	return position, nil
}

// Stop ends the epoch loop. This is useful if you need to free all resources
// associated with a Server.
func (s *Server) Stop() {
	close(s.stopper)
}
