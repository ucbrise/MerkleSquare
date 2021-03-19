// Package merkleclt contains client functions to make requests to
// merkle service.
package merkleclt

import (
	"context"
	"strconv"

	"github.com/ucbrise/MerkleSquare/grpcint"
	"github.com/immesys/bw2/crypto"
	"google.golang.org/grpc"
)

// Client is a client library for verifier operations.
type Client interface {
	Register(ctx context.Context, req *grpcint.RegisterRequest) (
		*grpcint.RegisterResponse, error)
	Append(ctx context.Context, req *grpcint.AppendRequest,
		masterSK, masterVK, key []byte) (*grpcint.AppendResponse, []byte, error)
	LookUpMK(ctx context.Context, req *grpcint.LookUpMKRequest) (
		*grpcint.LookUpMKResponse, error)
	LookUpPK(ctx context.Context, req *grpcint.LookUpPKRequest) (
		*grpcint.LookUpPKResponse, error)
	LookUpMKVerify(ctx context.Context, req *grpcint.LookUpMKVerifyRequest) (
		*grpcint.LookUpMKVerifyResponse, error)
	LookUpPKVerify(ctx context.Context, req *grpcint.LookUpPKVerifyRequest) (
		*grpcint.LookUpPKVerifyResponse, error)
	GetNewCheckPoint(ctx context.Context, req *grpcint.GetNewCheckPointRequest) (
		*grpcint.GetNewCheckPointResponse, error)
	GetMasterKeyProof(ctx context.Context, req *grpcint.GetMasterKeyProofRequest) (
		*grpcint.GetMasterKeyProofResponse, error)
	GetPublicKeyProof(ctx context.Context,
		req *grpcint.GetPublicKeyProofRequest) (*grpcint.GetPublicKeyProofResponse, error)
	GetLookUpProof(ctx context.Context, req *grpcint.GetLookUpProofRequest) (
		*grpcint.GetLookUpProofResponse, error)
	GetMonitoringProofForTest(ctx context.Context, req *grpcint.GetMonitoringProofForTestRequest) (
		*grpcint.GetMonitoringProofForTestResponse, error)
}

// assert that merkleClient implements merkleclt.Client interfact
var _ Client = (*merkleClient)(nil)

// merkleClient is an implementation of merkleclt.Client
type merkleClient struct {
	client grpcint.MerkleSquareClient
}

// NewMerkleClient creates and returns a connection to the merkleSquare server.
func NewMerkleClient(address string) (Client, error) {
	merkleConn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	grpcClient := grpcint.NewMerkleSquareClient(merkleConn)
	return &merkleClient{client: grpcClient}, nil
}

// NewMerkleClientWithMaxMsgSize creates and returns a connection to the merkleSquare server.
func NewMerkleClientWithMaxMsgSize(address string, maxMsgSize int) (Client, error) {
	merkleConn, err := grpc.Dial(address,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(maxMsgSize),
			grpc.MaxCallRecvMsgSize(maxMsgSize)),
		grpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	grpcClient := grpcint.NewMerkleSquareClient(merkleConn)
	return &merkleClient{client: grpcClient}, nil
}

func (m *merkleClient) Register(ctx context.Context, req *grpcint.RegisterRequest) (
	*grpcint.RegisterResponse, error) {
	return m.client.Register(ctx, req)
}

func (m *merkleClient) Append(ctx context.Context, req *grpcint.AppendRequest,
	masterSK, masterVK, key []byte) (*grpcint.AppendResponse, []byte, error) {
	stream, err := m.client.Append(ctx)
	if err != nil {
		return nil, nil, err
	}

	stream.Send(req)

	response, err := stream.Recv()
	if err != nil {
		return nil, nil, err
	}

	signature := make([]byte, 64)
	crypto.SignBlob(masterSK, masterVK, signature,
		append(key, []byte(strconv.Itoa(int(response.GetPos().GetPos())))...))
	req.Signature = signature
	stream.Send(req)

	response, err = stream.Recv()
	if err != nil {
		return nil, nil, err
	}

	stream.CloseSend()

	return response, signature, nil
}

func (m *merkleClient) LookUpMK(ctx context.Context,
	req *grpcint.LookUpMKRequest) (
	*grpcint.LookUpMKResponse, error) {
	return m.client.LookUpMK(ctx, req)
}

func (m *merkleClient) LookUpPK(ctx context.Context,
	req *grpcint.LookUpPKRequest) (
	*grpcint.LookUpPKResponse, error) {
	return m.client.LookUpPK(ctx, req)
}

func (m *merkleClient) LookUpMKVerify(ctx context.Context,
	req *grpcint.LookUpMKVerifyRequest) (
	*grpcint.LookUpMKVerifyResponse, error) {
	return m.client.LookUpMKVerify(ctx, req)
}

func (m *merkleClient) LookUpPKVerify(ctx context.Context,
	req *grpcint.LookUpPKVerifyRequest) (
	*grpcint.LookUpPKVerifyResponse, error) {
	return m.client.LookUpPKVerify(ctx, req)
}

func (m *merkleClient) GetNewCheckPoint(ctx context.Context,
	req *grpcint.GetNewCheckPointRequest) (
	*grpcint.GetNewCheckPointResponse, error) {
	return m.client.GetNewCheckPoint(ctx, req)
}

func (m *merkleClient) GetMasterKeyProof(ctx context.Context,
	req *grpcint.GetMasterKeyProofRequest) (
	*grpcint.GetMasterKeyProofResponse, error) {
	return m.client.GetMasterKeyProof(ctx, req)
}

func (m *merkleClient) GetPublicKeyProof(ctx context.Context,
	req *grpcint.GetPublicKeyProofRequest) (
	*grpcint.GetPublicKeyProofResponse, error) {
	return m.client.GetPublicKeyProof(ctx, req)
}

func (m *merkleClient) GetLookUpProof(ctx context.Context,
	req *grpcint.GetLookUpProofRequest) (
	*grpcint.GetLookUpProofResponse, error) {
	return m.client.GetLookUpProof(ctx, req)
}

func (m *merkleClient) GetMonitoringProofForTest(ctx context.Context,
	req *grpcint.GetMonitoringProofForTestRequest) (
	*grpcint.GetMonitoringProofForTestResponse, error) {
	return m.client.GetMonitoringProofForTest(ctx, req)
}
