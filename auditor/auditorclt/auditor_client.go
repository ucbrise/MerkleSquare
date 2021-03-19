// Package auditorclt contains client functions to make requests to
// auditor service.
package auditorclt

import (
	"context"

	"github.com/ucbrise/MerkleSquare/grpcint"
	"google.golang.org/grpc"
)

// Client is a client library for auditor operations.
type Client interface {
	// GetEpochUpdate fetches latest verified checkpoint from the auditor.
	GetEpochUpdate(ctx context.Context) (*grpcint.GetEpochUpdateResponse, error)
}

// assert that auditorClient implements auditorclt.Client interfact
var _ Client = (*auditorClient)(nil)

// auditorClient is an implementation of auditorclt.Client
type auditorClient struct {
	client grpcint.AuditorClient
}

// NewAuditorClient creates and returns a connection to the auditor.
func NewAuditorClient(address string) (Client, error) {
	auditorConn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	grpcClient := grpcint.NewAuditorClient(auditorConn)
	return &auditorClient{client: grpcClient}, nil
}

// GetEpochUpdate fetches latest verified checkpoint from the auditor.
func (a *auditorClient) GetEpochUpdate(ctx context.Context) (
	*grpcint.GetEpochUpdateResponse, error) {
	return a.client.GetEpochUpdate(ctx, &grpcint.GetEpochUpdateRequest{})
}
