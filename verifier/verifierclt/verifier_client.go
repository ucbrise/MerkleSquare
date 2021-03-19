// Package verifierclt contains client functions to make requests to
// verifier service.
package verifierclt

import (
	"context"

	"github.com/ucbrise/MerkleSquare/grpcint"
	"google.golang.org/grpc"
)

// Client is a client library for verifier operations.
type Client interface {
	VerifyRegisterAsync(ctx context.Context,
		req *grpcint.RegisterRequest, resp *grpcint.RegisterResponse) error
	VerifyAppendAsync(ctx context.Context, req *grpcint.VerifyAppendRequest) error
	VerifyLookUpMKAsync(ctx context.Context,
		req *grpcint.LookUpMKRequest, resp *grpcint.LookUpMKResponse) error
	VerifyLookUpPKAsync(ctx context.Context,
		req *grpcint.LookUpPKRequest, resp *grpcint.LookUpPKResponse) error
}

// assert that verifierClient implements verifierclt.Client interfact
var _ Client = (*verifierClient)(nil)

// verifierClient is an implementation of verifierclt.Client
type verifierClient struct {
	client grpcint.VerifierClient
}

// NewVerifierClient creates and returns a connection to the verifier.
func NewVerifierClient(address string) (Client, error) {
	verifierConn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	grpcClient := grpcint.NewVerifierClient(verifierConn)
	return &verifierClient{client: grpcClient}, nil
}

// VerifyRegisterAsync sends a request to verify a register operation performed by
// the client. This verification is done asynchronously by the verifier daemon.
func (v *verifierClient) VerifyRegisterAsync(ctx context.Context,
	req *grpcint.RegisterRequest, resp *grpcint.RegisterResponse) error {
	verifierRequest := &grpcint.VerifyRegisterRequest{
		Usr:       req.GetUsr(),
		VrfKey:    resp.GetVrfKey(),
		Key:       req.GetKey(),
		Signature: req.GetSignature(),
		Pos:       resp.GetPos(),
	}
	_, err := v.client.VerifyRegisterAsync(ctx, verifierRequest)
	return err
}

// VerifyAppendAsync sends a request to verify an append operation performed by
// the client. This verification is done asynchronously by the verifier daemon.
func (v *verifierClient) VerifyAppendAsync(ctx context.Context,
	req *grpcint.VerifyAppendRequest) error {
	_, err := v.client.VerifyAppendAsync(ctx, req)
	return err
}

// VerifyLookUpMKAsync sends a request to verify a lookup master key operation
// performed by the client. This verification is done asynchronously by the
// verifier daemon.
func (v *verifierClient) VerifyLookUpMKAsync(ctx context.Context,
	req *grpcint.LookUpMKRequest, resp *grpcint.LookUpMKResponse) error {
	verifierRequest := &grpcint.VerifyLookUpRequest{
		IsMasterKey: true,
		Usr:         req.GetUsr(),
		Vrf:         resp.GetVrfKey(),
		MasterKey:   resp.GetImk().GetMasterKey(),
		Signature:   resp.Signature,
		Pos:         resp.GetImk().GetPos(),
	}
	_, err := v.client.VerifyLookUpAsync(ctx, verifierRequest)
	return err
}

// VerifyLookUpPKAsync sends a request to verify a lookup public key operation
// performed by the client. This verification is done asynchronously by the
// verifier daemon.
func (v *verifierClient) VerifyLookUpPKAsync(ctx context.Context,
	req *grpcint.LookUpPKRequest, resp *grpcint.LookUpPKResponse) error {
	verifierRequest := &grpcint.VerifyLookUpRequest{
		IsMasterKey:   false,
		Usr:           req.GetUsr(),
		Vrf:           resp.GetVrfKey(),
		EncryptionKey: resp.GetIek().GetPublicKey(),
		Signature:     resp.Signature,
		Pos:           resp.GetIek().GetPos(),
	}
	_, err := v.client.VerifyLookUpAsync(ctx, verifierRequest)
	return err
}
