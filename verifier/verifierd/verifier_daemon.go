// Package verifierd contains implementations for verifier API.
package verifierd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/ucbrise/MerkleSquare/auditor/auditorclt"
	"github.com/ucbrise/MerkleSquare/core"
	"github.com/ucbrise/MerkleSquare/grpcint"
	"github.com/ucbrise/MerkleSquare/merkleserver/merkleclt"
)

type Verifier struct {
	merkleClient  merkleclt.Client
	auditorClient auditorclt.Client

	RegisterRequests []*KeyRegisterRequest
	RegisterLock     *sync.Mutex
	AppendRequests   []*KeyAppendRequest
	AppendLock       *sync.Mutex
	LookupRequests   []*KeyLookUpRequest
	LookupLock       *sync.Mutex

	//map from user to hashes of all keys user has ever uploaded
	keys     map[string][]core.KeyHash
	keysLock *sync.Mutex

	verifyCycleDuration time.Duration
	stopper             chan struct{}
}

type KeyLookUpRequest struct {
	ProofRequest *grpcint.GetLookUpProofRequest
	signature    []byte
	vrf          []byte
}

type KeyRegisterRequest struct {
	ProofRequest *grpcint.GetMasterKeyProofRequest
	signature    []byte
	vrf          []byte
}

type KeyAppendRequest struct {
	ProofRequest *grpcint.GetPublicKeyProofRequest
	signature    []byte
	vrf          []byte
	nodeHash     []byte
}

func NewVerifier(merkleServerAddr string, auditorServerAddr string,
	verifyCycleDuration time.Duration) (*Verifier, error) {

	server := &Verifier{
		RegisterRequests:    make([]*KeyRegisterRequest, 0),
		RegisterLock:        &sync.Mutex{},
		AppendLock:          &sync.Mutex{},
		LookupRequests:      make([]*KeyLookUpRequest, 0),
		LookupLock:          &sync.Mutex{},
		keys:                make(map[string][]core.KeyHash),
		keysLock:            &sync.Mutex{},
		verifyCycleDuration: verifyCycleDuration,
	}
	var err error

	server.merkleClient, err = merkleclt.NewMerkleClient(merkleServerAddr)
	if err != nil {
		return nil, errors.New("could not initialize merkle client")
	}
	server.auditorClient, err = auditorclt.NewAuditorClient(auditorServerAddr)
	if err != nil {
		return nil, errors.New("could not initialize auditor client")
	}

	if verifyCycleDuration != 0 {
		go server.VerifyLoop(time.Unix(0, time.Now().Add(verifyCycleDuration).UnixNano()))
	}

	return server, nil
}

func (v *Verifier) VerifyLoop(firstVerifyTime time.Time) {
	firstVerifyDuration := firstVerifyTime.Sub(time.Now())
	firstVerifyTimer := time.NewTimer(firstVerifyDuration)
	var verifyTicker *time.Ticker
	until := firstVerifyTimer.C
verifyLoop:
	for {
		select {
		case <-until:
			fmt.Println()
			fmt.Println("Start verify cycle!", time.Now())
			if firstVerifyTimer != nil {
				firstVerifyTimer.Stop()
				firstVerifyTimer = nil
				verifyTicker = time.NewTicker(v.verifyCycleDuration)
				until = verifyTicker.C
			}

			v.Verify()

		case <-v.stopper:
			fmt.Println("Stopping epoch loop!")
			break verifyLoop
		}
	}
	if firstVerifyTimer != nil {
		firstVerifyTimer.Stop()
	}
	if verifyTicker != nil {
		verifyTicker.Stop()
	}
}

func (v *Verifier) Verify() {
	ctx := context.Background()
	auditorResponse, err := v.auditorClient.GetEpochUpdate(ctx)
	if err != nil {
		fmt.Println("Could not query auditor server, skipping this verify cycle")
		return
	}
	var digest = new(core.Digest)
	marshaledDigest := auditorResponse.GetCkPoint().GetMarshaledDigest()
	json.Unmarshal(marshaledDigest, &digest)
	fmt.Printf("using digest with numLeaves: %v and epoch: %v \n", digest.Size,
		auditorResponse.GetCkPoint().GetEpoch())

	//Verify register proofs
	v.RegisterLock.Lock()
	unAttemptedRegisters := make([]*KeyRegisterRequest, 0)
	fmt.Printf("Number of first values verified in this epoch: %v\n", len(v.RegisterRequests))
	for _, registerRequest := range v.RegisterRequests {
		attempted, _ := v.VerifyRegister(ctx, registerRequest, digest)

		// After checking the first-value proof, the first append will be added
		// to the AppendRequests as the normal appends.
		if attempted {
			ProofRequest := grpcint.GetPublicKeyProofRequest{
				Usr:    registerRequest.ProofRequest.GetUsr(),
				Key:    &grpcint.EncryptionKey{Ek: registerRequest.ProofRequest.GetKey().GetMk()},
				Pos:    registerRequest.ProofRequest.GetPos(),
				Height: 0,
			}
			appendRequest := KeyAppendRequest{
				ProofRequest: &ProofRequest,
				signature:    registerRequest.signature,
				vrf:          registerRequest.vrf,
				nodeHash: core.ComputeLeafNodeHash(registerRequest.vrf,
					registerRequest.ProofRequest.GetKey().GetMk(), registerRequest.signature,
					uint32(registerRequest.ProofRequest.GetPos().GetPos())),
			}
			v.AppendLock.Lock()
			v.AppendRequests = append(v.AppendRequests, &appendRequest)
			v.AppendLock.Unlock()
		} else {
			unAttemptedRegisters = append(unAttemptedRegisters, registerRequest)
		}
	}
	v.RegisterRequests = unAttemptedRegisters
	v.RegisterLock.Unlock()

	//Verify keys appended by the user.
	v.AppendLock.Lock()
	fmt.Printf("Number of values verified in this epoch: %v\n", len(v.AppendRequests))
	for _, appendRequest := range v.AppendRequests {
		v.VerifyAppend(ctx, appendRequest, digest)
	}
	v.AppendLock.Unlock()

	//Verify lookup keys.
	v.LookupLock.Lock()
	unAttemptedLookUps := make([]*KeyLookUpRequest, 0)
	for _, lookUpRequest := range v.LookupRequests {
		attempted, _ := v.VerifyLookUp(ctx, lookUpRequest, digest)
		if !attempted {
			unAttemptedLookUps = append(unAttemptedLookUps, lookUpRequest)
		}
	}

	//Only keeps unattmpted lookups to run in next iteration,
	//discarding lookups that have already been (dis)proven.
	v.LookupRequests = unAttemptedLookUps
	v.LookupLock.Unlock()
}

func (v *Verifier) VerifyRegister(ctx context.Context,
	registerRequest *KeyRegisterRequest, digest *core.Digest) (
	attempted bool, proven bool) {

	proofrequest := registerRequest.ProofRequest
	pos := uint32(proofrequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false
	}
	proofrequest.Size = uint64(digest.Size)
	proofResponse, err := v.merkleClient.GetMasterKeyProof(ctx, proofrequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false
	}
	attempted = true
	var registerProof core.NonExistenceProof
	json.Unmarshal(proofResponse.GetProof(), &registerProof)
	proven = core.VerifyNonexistenceProof(registerRequest.vrf, pos, digest, &registerProof)
	if !proven {
		fmt.Println("WARNING: could not prove nonexistence")
	}
	return
}

func (v *Verifier) VerifyRegisterForSize(ctx context.Context,
	registerRequest *KeyRegisterRequest, digest *core.Digest) (bool, bool, int) {

	proofrequest := registerRequest.ProofRequest
	pos := uint32(proofrequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false, 0
	}
	proofrequest.Size = uint64(digest.Size)
	proofResponse, err := v.merkleClient.GetMasterKeyProof(ctx, proofrequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false, 0
	}
	// attempted := true
	var registerProof core.NonExistenceProof
	json.Unmarshal(proofResponse.GetProof(), &registerProof)
	proven := core.VerifyNonexistenceProof(registerRequest.vrf, pos, digest, &registerProof)
	if !proven {
		fmt.Println("WARNING: could not prove nonexistence")
	}

	return true, true, proto.Size(proofResponse)
}

func (v *Verifier) VerifyAppend(ctx context.Context,
	appendRequest *KeyAppendRequest, digest *core.Digest) (
	attempted bool, proven bool) {

	//var err error
	proofrequest := appendRequest.ProofRequest
	pos := uint32(proofrequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false
	}
	proofrequest.Size = uint64(digest.Size)
	//VerifyExistenceProof
	proofResponse, err := v.merkleClient.GetPublicKeyProof(ctx, proofrequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false
	}
	attempted = true
	var appendProof core.MerkleExistenceProof
	json.Unmarshal(proofResponse.GetProof(), &appendProof)

	//appendRequest.nodehash = core.ComputeLeafNodeHash(
	// appendRequest.vrf, proofrequest.Key.GetEk(), appendRequest.signature, pos)
	oldHashes := v.keys[string(appendRequest.vrf)]
	proven, newNodeHash, newHeight := core.VerifyExistenceProof(digest,
		appendRequest.nodeHash, appendRequest.vrf, pos, proofrequest.GetHeight(),
		&appendProof, oldHashes)
	if !proven {
		fmt.Printf("WARNING: could not prove existence at position %v \n", pos)
	} else {
		appendRequest.nodeHash = newNodeHash
		proofrequest.Height = newHeight
	}
	return
}

func (v *Verifier) VerifyAppendForSize(ctx context.Context,
	appendRequest *KeyAppendRequest, digest *core.Digest) (bool, bool, int) {
	//var err error
	proofrequest := appendRequest.ProofRequest
	pos := uint32(proofrequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false, 0
	}
	proofrequest.Size = uint64(digest.Size)
	//VerifyExistenceProof
	proofResponse, err := v.merkleClient.GetPublicKeyProof(ctx, proofrequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false, 0
	}
	// attempted = true
	var appendProof core.MerkleExistenceProof
	json.Unmarshal(proofResponse.GetProof(), &appendProof)

	//appendRequest.nodehash = core.ComputeLeafNodeHash(appendRequest.vrf,
	// proofrequest.Key.GetEk(), appendRequest.signature, pos)
	oldHashes := v.keys[string(appendRequest.vrf)]
	proven, newNodeHash, newHeight := core.VerifyExistenceProof(digest,
		appendRequest.nodeHash, appendRequest.vrf, pos, proofrequest.GetHeight(),
		&appendProof, oldHashes)
	if !proven {
		fmt.Printf("WARNING: could not prove existence at position %v \n", pos)
	} else {
		appendRequest.nodeHash = newNodeHash
		proofrequest.Height = newHeight
	}

	return true, true, proto.Size(proofResponse)
}

func (v *Verifier) VerifyLookUp(ctx context.Context,
	lookUpRequest *KeyLookUpRequest, digest *core.Digest) (
	attempted bool, proven bool) {

	var err error
	ProofRequest := lookUpRequest.ProofRequest
	pos := uint32(ProofRequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false
	}
	ProofRequest.Size = uint64(digest.Size)
	proofResponse, err := v.merkleClient.GetLookUpProof(ctx, ProofRequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false
	}
	attempted = true
	if ProofRequest.GetIsMasterKey() {
		var mkProof core.MKProof
		json.Unmarshal(proofResponse.GetProof(), &mkProof)
		proven = core.VerifyMKProof(digest, lookUpRequest.vrf,
			ProofRequest.GetMasterKey().GetMk(), lookUpRequest.signature, pos, &mkProof)
	} else {
		var pkProof core.LatestPKProof
		json.Unmarshal(proofResponse.GetProof(), &pkProof)
		proven = core.VerifyPKProof(digest, lookUpRequest.vrf,
			ProofRequest.GetEncryptionKey().GetEk(), lookUpRequest.signature, pos, &pkProof)
	}
	if !proven {
		fmt.Printf("WARNING: could not prove lookup at position %v \n", pos)
	}
	return
}

func (v *Verifier) VerifyLookUpForSize(ctx context.Context,
	lookUpRequest *KeyLookUpRequest, digest *core.Digest) (bool, bool, int) {

	var err error
	ProofRequest := lookUpRequest.ProofRequest
	pos := uint32(ProofRequest.GetPos().GetPos())
	if pos >= digest.Size {
		fmt.Println("Key not published yet, trying again in next verify iteration")
		return false, false, 0
	}
	ProofRequest.Size = uint64(digest.Size)
	proofResponse, err := v.merkleClient.GetLookUpProof(ctx, ProofRequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return false, false, 0
	}
	// attempted = true
	var proven bool
	if ProofRequest.GetIsMasterKey() {
		var mkProof core.MKProof
		json.Unmarshal(proofResponse.GetProof(), &mkProof)
		proven = core.VerifyMKProof(digest, lookUpRequest.vrf,
			ProofRequest.GetMasterKey().GetMk(), lookUpRequest.signature, pos, &mkProof)
	} else {
		var pkProof core.LatestPKProof
		json.Unmarshal(proofResponse.GetProof(), &pkProof)
		proven = core.VerifyPKProof(digest, lookUpRequest.vrf,
			ProofRequest.GetEncryptionKey().GetEk(), lookUpRequest.signature, pos, &pkProof)
	}
	if !proven {
		fmt.Printf("WARNING: could not prove lookup at position %v \n", pos)
	}
	return true, true, proto.Size(proofResponse)
}

// Stop ends the epoch loop. This is useful if you need to free all resources
// associated with a Server.
func (v *Verifier) Stop() {
	close(v.stopper)
}
