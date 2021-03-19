// Package merklesrv contains implementations for merkle server API.
package merklesrv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/ucbrise/MerkleSquare/grpcint"

	"github.com/immesys/bw2/crypto"
)

func (s *Server) Register(ctx context.Context, req *grpcint.RegisterRequest) (
	*grpcint.RegisterResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	position, err := s.RegisterUserKey(ctx, req.GetUsr().GetUsername(),
		req.GetKey().GetMk(), req.GetSignature(), true)
	if err != nil {
		return nil, err
	}

	return &grpcint.RegisterResponse{
		Pos:    &grpcint.Position{Pos: position},
		VrfKey: s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
	}, nil
}

func (s *Server) Append(stream grpcint.MerkleSquare_AppendServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	ctx := context.Background()

	user, key := req.GetUsr().GetUsername(), req.GetEk().GetEk()
	mkSerialized, _ := s.Storage.Get(ctx, append(user, []byte("MK")...))
	queryString := append(user, []byte("PK")...)
	if mkSerialized == nil {
		return errors.New("User is not registered")
	}
	var mk KeyRecord
	err = json.Unmarshal(mkSerialized, &mk)
	if err != nil {
		return err
	}

	s.LastPosLock.Lock()
	s.appendLock.Lock()
	position := s.LastPos
	s.LastPos++
	//Send position
	var response = &grpcint.AppendResponse{
		Pos: &grpcint.Position{Pos: position},
	}
	stream.Send(response)
	req, err = stream.Recv()
	if err != nil {
		return err
	}
	signature := req.GetSignature()
	//Verify
	if !crypto.VerifyBlob(mk.Key, signature,
		append(key, []byte(strconv.Itoa(int(position)))...)) {
		return errors.New("Verification failed")
	}
	//Add to merkle tree
	s.MerkleSquare.Append(s.vrfPrivKey.Compute(user), key, signature)
	s.appendLock.Unlock()
	s.LastPosLock.Unlock()

	//4. Add to K-V store
	var serializedKey []byte
	// Prepend to existing entry
	original, _ := s.Storage.Get(ctx, queryString)
	keyrecord := make([]KeyRecord, 1)
	keyrecord[0] = KeyRecord{
		Position:  position,
		Signature: signature,
		Key:       key,
	}
	if original == nil {
		serializedKey, _ = json.Marshal(keyrecord)
	} else {
		var deserialized []KeyRecord
		json.Unmarshal(original, &deserialized)
		serializedKey, _ = json.Marshal(append(keyrecord, deserialized...))
	}
	s.Storage.Put(ctx, queryString, serializedKey)
	response.VrfKey = s.vrfPrivKey.Compute(req.GetUsr().GetUsername())
	response.Completed = true
	stream.Send(response)
	return nil
}

func (s *Server) LookUpMK(ctx context.Context, req *grpcint.LookUpMKRequest) (
	*grpcint.LookUpMKResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, sign, pos, err := s.GetUserKey(ctx, req.GetUsr().GetUsername(), true, 0)
	if err != nil {
		return nil, err
	}

	return &grpcint.LookUpMKResponse{
		Imk: &grpcint.IndexedMK{
			Pos:       &grpcint.Position{Pos: pos},
			MasterKey: &grpcint.MasterKey{Mk: key},
		},
		Signature: sign,
		VrfKey:    s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
	}, nil
}

func (s *Server) LookUpPK(ctx context.Context, req *grpcint.LookUpPKRequest) (
	*grpcint.LookUpPKResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var reqPos uint64
	if req.GetPos() == nil {
		s.epochLock.RLock()
		reqPos = s.PublishedPos
		s.epochLock.RUnlock()
	} else {
		reqPos = req.GetPos().GetPos()
	}

	key, sign, pos, err := s.GetUserKey(ctx, req.GetUsr().GetUsername(), false, reqPos)
	if err != nil {
		return nil, err
	}

	return &grpcint.LookUpPKResponse{
		Iek: &grpcint.IndexedEK{
			Pos:       &grpcint.Position{Pos: pos},
			PublicKey: &grpcint.EncryptionKey{Ek: key},
		},
		Signature: sign,
		VrfKey:    s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
	}, nil
}

func (s *Server) LookUpMKVerify(ctx context.Context,
	req *grpcint.LookUpMKVerifyRequest) (
	*grpcint.LookUpMKVerifyResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Size == 0 {
		s.epochLock.RLock()
		req.Size = s.PublishedPos
		s.epochLock.RUnlock()
	}

	key, sign, pos, err := s.GetUserKey(ctx, req.GetUsr().GetUsername(), true, 0)
	vrfKey := s.vrfPrivKey.Compute(req.GetUsr().GetUsername())
	if err != nil {
		return nil, err
	}

	proof := s.MerkleSquare.ProveFirst(vrfKey, key, uint32(pos), uint32(req.Size))
	marshaledProof, err := json.Marshal(proof)
	return &grpcint.LookUpMKVerifyResponse{
		Imk: &grpcint.IndexedMK{
			Pos:       &grpcint.Position{Pos: pos},
			MasterKey: &grpcint.MasterKey{Mk: key},
		},
		Signature: sign,
		VrfKey:    vrfKey,
		Proof:     marshaledProof,
	}, err
}

func (s *Server) LookUpPKVerify(ctx context.Context, req *grpcint.LookUpPKVerifyRequest) (
	*grpcint.LookUpPKVerifyResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Size == 0 {
		s.epochLock.RLock()
		req.Size = s.PublishedPos
		s.epochLock.RUnlock()
	}

	key, sign, pos, err := s.GetUserKey(ctx, req.GetUsr().GetUsername(), false, req.Size)
	vrfKey := s.vrfPrivKey.Compute(req.GetUsr().GetUsername())
	if err != nil {
		return nil, err
	}

	proof := s.MerkleSquare.ProveLatest(vrfKey, key, uint32(pos), uint32(req.Size))
	marshaledProof, err := json.Marshal(proof)

	return &grpcint.LookUpPKVerifyResponse{
		Iek: &grpcint.IndexedEK{
			Pos:       &grpcint.Position{Pos: pos},
			PublicKey: &grpcint.EncryptionKey{Ek: key},
		},
		Signature: sign,
		VrfKey:    vrfKey,
		Proof:     marshaledProof,
	}, err
}

func (s *Server) GetNewCheckPoint(ctx context.Context,
	req *grpcint.GetNewCheckPointRequest) (
	*grpcint.GetNewCheckPointResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if req.OldSize > s.PublishedPos {
		return nil, errors.New("Auditor expects more leaves than what server published")
	}

	digest, err := json.Marshal(s.PublishedDigest)
	if err != nil {
		return nil, err
	}

	var marshaledProof []byte
	proof, ok := s.extensionProofCache[ExtensionProofKey{req.OldSize, s.PublishedPos}]
	if s.CacheExtensionProofs && ok {
		marshaledProof = proof
	} else {
		extensionProof := s.MerkleSquare.GenerateExtensionProof(
			uint32(req.OldSize), uint32(s.PublishedPos))
		marshaledProof, err = json.Marshal(extensionProof)
		if err != nil {
			return nil, err
		}
		if s.CacheExtensionProofs {
			s.extensionProofCache[ExtensionProofKey{req.OldSize, s.PublishedPos}] = marshaledProof
		}
	}

	return &grpcint.GetNewCheckPointResponse{
		CkPoint: &grpcint.CheckPoint{
			MarshaledDigest: digest,
			NumLeaves:       s.PublishedPos,
			Epoch:           s.epoch,
		},
		Proof: marshaledProof,
	}, nil
}

func (s *Server) GetMasterKeyProof(ctx context.Context,
	req *grpcint.GetMasterKeyProofRequest) (
	*grpcint.GetMasterKeyProofResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof := s.MerkleSquare.ProveNonexistence(
		s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
		uint32(req.GetPos().GetPos()), uint32(req.Size))
	marshaledProof, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	return &grpcint.GetMasterKeyProofResponse{
		Proof: marshaledProof,
	}, nil
}

func (s *Server) GetPublicKeyProof(ctx context.Context,
	req *grpcint.GetPublicKeyProofRequest) (*grpcint.GetPublicKeyProofResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Size == 0 {
		s.epochLock.RLock()
		req.Size = s.PublishedPos
		s.epochLock.RUnlock()
	}
	proof := s.MerkleSquare.GenerateExistenceProof(
		s.vrfPrivKey.Compute(req.GetUsr().GetUsername()), uint32(req.GetPos().GetPos()),
		req.GetHeight(), uint32(req.Size))
	marshaledProof, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	return &grpcint.GetPublicKeyProofResponse{
		Proof: marshaledProof,
	}, nil
}

func (s *Server) GetMonitoringProofForTest(ctx context.Context,
	req *grpcint.GetMonitoringProofForTestRequest) (
	*grpcint.GetMonitoringProofForTestResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Size == 0 {
		s.epochLock.RLock()
		req.Size = s.PublishedPos
		s.epochLock.RUnlock()
	}

	proof := s.MerkleSquare.GenerateExistenceProof(
		s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
		uint32(req.GetPos().GetPos()), req.GetHeight(), uint32(req.Size))
	marshaledProof, err := json.Marshal(proof)
	if err != nil {
		fmt.Println(uint32(req.GetPos().GetPos()))
		fmt.Println(req.GetHeight())
		fmt.Println(uint32(req.Size))
		fmt.Println(err.Error())
		return nil, err
	}

	return &grpcint.GetMonitoringProofForTestResponse{
		Proof: marshaledProof,
	}, nil
}

func (s *Server) GetLookUpProof(ctx context.Context,
	req *grpcint.GetLookUpProofRequest) (
	*grpcint.GetLookUpProofResponse, error) {
	var err error
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var marshaledProof []byte
	if req.GetIsMasterKey() {
		proof := s.MerkleSquare.ProveFirst(
			s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
			req.GetMasterKey().GetMk(), uint32(req.GetPos().GetPos()), uint32(req.Size))
		marshaledProof, err = json.Marshal(proof)
	} else {
		proof := s.MerkleSquare.ProveLatest(
			s.vrfPrivKey.Compute(req.GetUsr().GetUsername()),
			req.GetEncryptionKey().GetEk(), uint32(req.GetPos().GetPos()), uint32(req.Size))
		marshaledProof, err = json.Marshal(proof)
	}
	if err != nil {
		return nil, err
	}

	return &grpcint.GetLookUpProofResponse{
		Proof: marshaledProof,
	}, nil
}
