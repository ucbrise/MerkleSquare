package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/ucbrise/MerkleSquare/auditor/auditorclt"
	"github.com/ucbrise/MerkleSquare/core"
	"github.com/ucbrise/MerkleSquare/grpcint"
	"github.com/ucbrise/MerkleSquare/merkleserver/merkleclt"
	"github.com/ucbrise/MerkleSquare/verifier/verifierclt"

	"github.com/immesys/bw2/crypto"
)

// Client represents a connection to the server and the verification daemon,
// over which operation and verification can be performed.
type Client struct {
	merkleClient   merkleclt.Client
	auditorClient  auditorclt.Client
	verifierClient verifierclt.Client

	masterKeys map[string]MasterKeyRecord
}

type MasterKeyRecord struct {
	masterSK []byte
	masterVK []byte
}

// NewClient connects to the server and the daemon, and returns a Client
// representing that connection.
func NewClient(serverAddr string, auditorAddr string, verifierAddr string) (
	*Client, error) {

	var err error
	c := Client{
		masterKeys: make(map[string]MasterKeyRecord),
	}
	c.merkleClient, err = merkleclt.NewMerkleClient(serverAddr)
	if err != nil {
		return nil, err
	}
	if auditorAddr != "" {
		c.auditorClient, err = auditorclt.NewAuditorClient(auditorAddr)
		if err != nil {
			return nil, err
		}
	}
	if verifierAddr != "" {
		c.verifierClient, err = verifierclt.NewVerifierClient(verifierAddr)
		if err != nil {
			return nil, err
		}
	}
	return &c, nil
}

//Register user and the corresponding public master key to the server.
func (c *Client) Register(ctx context.Context, username []byte,
	masterSK []byte, masterVK []byte) (uint64, error) {
	response, err := c.registerInt(ctx, username, masterSK, masterVK)
	return response.GetPos().GetPos(), err
}

// RegisterForSize returns the size of the server's response.
// This function is used for test.
func (c *Client) RegisterForSize(ctx context.Context, username []byte,
	masterSK []byte, masterVK []byte) (int, error) {
	response, err := c.registerInt(ctx, username, masterSK, masterVK)
	return proto.Size(response), err
}

// registerInt is the internal implementation to register a user
func (c *Client) registerInt(ctx context.Context, username []byte,
	masterSK []byte, masterVK []byte) (
	*grpcint.RegisterResponse, error) {

	signature := make([]byte, 64)
	crypto.SignBlob(masterSK, masterVK, signature, masterVK)

	request := &grpcint.RegisterRequest{
		Usr:       &grpcint.Username{Username: username},
		Key:       &grpcint.MasterKey{Mk: masterVK},
		Signature: signature,
	}
	response, err := c.merkleClient.Register(ctx, request)
	if err != nil {
		return nil, err
	}
	var verifierErr error
	if c.verifierClient != nil {
		verifierErr = c.verifierClient.VerifyRegisterAsync(ctx, request, response)
	}
	c.masterKeys[string(username)] = MasterKeyRecord{
		masterSK: masterSK,
		masterVK: masterVK,
	}
	return response, verifierErr
}

// Append adds a public key for the user to the key transparency infrastructure.
func (c *Client) Append(ctx context.Context, username []byte, key []byte) (
	uint64, *grpcint.VerifyAppendRequest, error) {
	response, verifierReq, err := c.appendInt(ctx, username, key)
	return response.GetPos().GetPos(), verifierReq, err
}

// AppendForSize adds a public key for the user to the key transparency infrastructure
// and returns the size of response returned by the server.
func (c *Client) AppendForSize(ctx context.Context, username []byte, key []byte) (int, error) {
	response, _, err := c.appendInt(ctx, username, key)
	return proto.Size(response), err
}

// appendInt is the internal implementation to add a public key for the user.
func (c *Client) appendInt(ctx context.Context, username []byte, key []byte) (
	*grpcint.AppendResponse, *grpcint.VerifyAppendRequest, error) {
	masterKeyInfo, ok := c.masterKeys[string(username)]
	if !ok {
		return nil, nil, errors.New("masterkey does not exist")
	}

	request := &grpcint.AppendRequest{
		Usr: &grpcint.Username{Username: username},
		Ek:  &grpcint.EncryptionKey{Ek: key},
	}
	response, signature, err := c.merkleClient.Append(ctx, request,
		masterKeyInfo.masterSK, masterKeyInfo.masterVK, key)
	if err != nil {
		return nil, nil, err
	}

	var verifierErr error
	var verifierRequest *grpcint.VerifyAppendRequest
	if c.verifierClient != nil {
		verifierRequest = &grpcint.VerifyAppendRequest{
			Usr:       request.GetUsr(),
			VrfKey:    response.GetVrfKey(),
			Key:       request.GetEk(),
			Signature: signature,
			Pos:       response.GetPos(),
		}
		verifierErr = c.verifierClient.VerifyAppendAsync(ctx, verifierRequest)
	}
	return response, verifierRequest, verifierErr
}

// LookUpMK takes a name and returns the associated master key of the user, if user exists.
// Verification of the response is done asynchronously by the verifier daemon.
func (c *Client) LookUpMK(ctx context.Context, username []byte) ([]byte, uint64, error) {
	var request = &grpcint.LookUpMKRequest{
		Usr: &grpcint.Username{Username: username},
	}
	response, err := c.merkleClient.LookUpMK(ctx, request)
	if err != nil {
		return response.GetImk().GetMasterKey().GetMk(), response.GetImk().GetPos().GetPos(), err
	}

	var verifierErr error
	if c.verifierClient != nil {
		verifierErr = c.verifierClient.VerifyLookUpMKAsync(ctx, request, response)
	}
	return response.GetImk().GetMasterKey().GetMk(), response.GetImk().GetPos().GetPos(), verifierErr
}

// LookUpMKVerify takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
func (c *Client) LookUpMKVerify(ctx context.Context, username []byte) ([]byte, uint64, error) {
	response, err := c.lookUpMKVerifyInt(ctx, username)
	if err != nil {
		return nil, 0, err
	}
	return response.GetImk().GetMasterKey().GetMk(),
		response.GetImk().GetPos().GetPos(), nil
}

// LookUpMKVerifyForTest takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
// This function returns more information relevant to testing compared to
// LookUpMKVerify.
func (c *Client) LookUpMKVerifyForTest(ctx context.Context, username []byte) (
	[]byte, uint64, []byte, []byte, error) {
	response, err := c.lookUpMKVerifyInt(ctx, username)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	return response.GetImk().GetMasterKey().GetMk(),
		response.GetImk().GetPos().GetPos(), response.GetVrfKey(), response.Signature, nil
}

// LookUpMKVerifyForSize takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
// This function returns the size of the response returned by the server.
func (c *Client) LookUpMKVerifyForSize(ctx context.Context, username []byte) (int, error) {
	response, err := c.lookUpMKVerifyInt(ctx, username)
	if err != nil {
		return 0, err
	}
	return proto.Size(response), nil
}

// lookUpMKVerifyInt is the internal function to look up the master key
// and verify the response synchronously.
func (c *Client) lookUpMKVerifyInt(ctx context.Context, username []byte) (
	*grpcint.LookUpMKVerifyResponse, error) {
	var numLeaves uint64
	var digest = &core.Digest{}

	if c.auditorClient != nil {
		auditorResponse, err := c.auditorClient.GetEpochUpdate(ctx)
		if err != nil {
			return nil, err
		}
		numLeaves = auditorResponse.CkPoint.GetNumLeaves()
		marshaledDigest := auditorResponse.GetCkPoint().GetMarshaledDigest()
		json.Unmarshal(marshaledDigest, &digest)
	} else {
		numLeaves = 0
	}

	var request = &grpcint.LookUpMKVerifyRequest{
		Size: numLeaves,
		Usr:  &grpcint.Username{Username: username},
	}
	response, err := c.merkleClient.LookUpMKVerify(ctx, request)
	if err != nil {
		return nil, err
	}

	masterKey := response.GetImk().GetMasterKey().GetMk()
	position := response.GetImk().GetPos().GetPos()

	if c.auditorClient != nil {
		var mkProof core.MKProof
		json.Unmarshal(response.GetProof(), &mkProof)
		proven := core.VerifyMKProof(digest, response.GetVrfKey(),
			masterKey, response.Signature, uint32(position), &mkProof)
		if !proven {
			fmt.Printf("WARNING: could not prove lookup at position %v \n", position)
			return nil, errors.New("WARNING: could not prove lookup")
		}
	}
	return response, nil
}

//LookUpPK takes a name and returns the latest published PK up until the last epoch, if one exists.
//This function will not return the master key if master key is the latest PK.
func (c *Client) LookUpPK(ctx context.Context, username []byte) ([]byte, uint64, error) {
	var serverRequest *grpcint.LookUpPKRequest

	if c.auditorClient != nil {
		auditorResponse, err := c.auditorClient.GetEpochUpdate(ctx)
		if err != nil {
			return nil, 0, err
		}
		serverRequest = &grpcint.LookUpPKRequest{
			Pos: &grpcint.Position{
				Pos: auditorResponse.CkPoint.GetNumLeaves(),
			},
			Usr: &grpcint.Username{Username: username},
		}
	} else {
		serverRequest = &grpcint.LookUpPKRequest{
			Pos: nil,
			Usr: &grpcint.Username{Username: username},
		}
	}

	serverResponse, err := c.merkleClient.LookUpPK(ctx, serverRequest)
	if err != nil {
		return serverResponse.GetIek().GetPublicKey().GetEk(), serverResponse.GetIek().GetPos().GetPos(), err
	}

	var verifierErr error
	if c.verifierClient != nil {
		verifierErr = c.verifierClient.VerifyLookUpPKAsync(ctx, serverRequest, serverResponse)
	}

	return serverResponse.GetIek().GetPublicKey().GetEk(),
		serverResponse.GetIek().GetPos().GetPos(), verifierErr
}

// LookUpPKVerify takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
func (c *Client) LookUpPKVerify(ctx context.Context, username []byte) ([]byte, uint64, error) {
	response, err := c.lookUpPKVerifyInt(ctx, username)
	if err != nil {
		return nil, 0, err
	}
	return response.GetIek().GetPublicKey().GetEk(), response.GetIek().GetPos().GetPos(), nil
}

// LookUpPKVerifyForTest takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
// This function returns more information relevant to testing compared to
// LookUpPKVerify.
func (c *Client) LookUpPKVerifyForTest(ctx context.Context, username []byte) ([]byte, uint64, []byte, []byte, error) {
	response, err := c.lookUpPKVerifyInt(ctx, username)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	return response.GetIek().GetPublicKey().GetEk(), response.GetIek().GetPos().GetPos(),
		response.GetVrfKey(), response.Signature, nil
}

// LookUpPKVerifyForSize takes a name and looks up the associated key/proof.
// Verification of the response is done synchronously during the API call.
// This function returns the size of the response returned by the server.
func (c *Client) LookUpPKVerifyForSize(ctx context.Context, username []byte) (int, error) {
	response, err := c.lookUpPKVerifyInt(ctx, username)
	if err != nil {
		return 0, err
	}
	return proto.Size(response), nil
}

// lookUpPKVerifyInt is the internal function to look up the latest public key
// for the user and verify the response synchronously.
func (c *Client) lookUpPKVerifyInt(ctx context.Context, username []byte) (
	*grpcint.LookUpPKVerifyResponse, error) {
	var numLeaves uint64
	var digest = new(core.Digest)

	if c.auditorClient != nil {
		auditorResponse, err := c.auditorClient.GetEpochUpdate(ctx)
		if err != nil {
			return nil, err
		}
		numLeaves = auditorResponse.CkPoint.GetNumLeaves()
		marshaledDigest := auditorResponse.GetCkPoint().GetMarshaledDigest()
		json.Unmarshal(marshaledDigest, &digest)
	} else {
		numLeaves = 0
	}

	serverRequest := &grpcint.LookUpPKVerifyRequest{
		Size: numLeaves,
		Usr:  &grpcint.Username{Username: username},
	}
	serverResponse, err := c.merkleClient.LookUpPKVerify(ctx, serverRequest)
	if err != nil {
		return serverResponse, err
	}

	encryptionKey := serverResponse.GetIek().GetPublicKey().GetEk()
	position := serverResponse.GetIek().GetPos().GetPos()

	if c.auditorClient != nil {
		var pkProof core.LatestPKProof
		json.Unmarshal(serverResponse.GetProof(), &pkProof)
		proven := core.VerifyPKProof(digest, serverResponse.GetVrfKey(), encryptionKey, serverResponse.Signature, uint32(position), &pkProof)
		if !proven {
			fmt.Printf("WARNING: could not prove lookup at position %v \n", position)
			return serverResponse, errors.New("WARNING: could not prove lookup")
		}
	}
	return serverResponse, nil
}

// MonitoringForSize takes a name, the position number in chronological forest,
// the height in the tree (recall that the owner can skip prefix trees that were
// checked in the past), the vrf (disabled right now), the encryption key (value),
// signature, and hash of the leaf node to obtain the size of the monitoring proof.
// This function is used for test purpose, and the verification daemon should perform
// the monitoring on behalf of the owner periodically.
func (c *Client) MonitoringForSize(ctx context.Context, username []byte,
	pos int, height int, vrf []byte, Ek []byte, signature []byte,
	keyhash []core.KeyHash) (int, error) {
	response, err := c.monitoringInt(ctx, username, pos, height, vrf,
		Ek, signature, keyhash)
	if err != nil {
		return 0, err
	}
	return proto.Size(response), nil
}

// monitoringInt is the internal function to obtain the moniroing proof for client.
func (c *Client) monitoringInt(ctx context.Context, username []byte,
	pos int, height int, vrf []byte, Ek []byte, signature []byte,
	keyhash []core.KeyHash) (*grpcint.GetPublicKeyProofResponse, error) {
	auditorResponse, err := c.auditorClient.GetEpochUpdate(ctx)
	if err != nil {
		fmt.Println("Could not query auditor server, skipping this verify cycle")
		return nil, err
	}
	var digest = new(core.Digest)
	marshaledDigest := auditorResponse.GetCkPoint().GetMarshaledDigest()
	json.Unmarshal(marshaledDigest, &digest)

	proofrequest := &grpcint.GetPublicKeyProofRequest{
		Usr: &grpcint.Username{
			Username: username,
		},
		Size: uint64(digest.Size),
		Pos: &grpcint.Position{
			Pos: uint64(pos),
		},
		Height: uint32(height),
	}

	proofResponse, err := c.merkleClient.GetPublicKeyProof(ctx, proofrequest)
	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return nil, err
	}

	if err != nil {
		fmt.Println("could not get proof, trying again in next verify iteration")
		return nil, err
	}

	var appendProof core.MerkleExistenceProof
	json.Unmarshal(proofResponse.GetProof(), &appendProof)

	nodeHash := core.ComputeLeafNodeHash(vrf, Ek, signature, uint32(pos))
	oldHashes := keyhash
	proven, _, _ := core.VerifyExistenceProof(digest, nodeHash, vrf, uint32(pos),
		uint32(height), &appendProof, oldHashes)
	if !proven {
		fmt.Printf("WARNING: could not prove existence at position %v \n", pos)
	}
	return proofResponse, nil
}

// RequestAuditorForSize obtain the size of the auditor's response.
// This function is used for test.
func (c *Client) RequestAuditorForSize(ctx context.Context) (int, error) {
	auditorResponse, err := c.auditorClient.GetEpochUpdate(ctx)
	if err != nil {
		return 0, err
	}
	return proto.Size(auditorResponse), nil
}
