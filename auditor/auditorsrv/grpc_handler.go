// Package auditorsrv contains server side implementations for auditor API.
package auditorsrv

import (
	"context"

	"github.com/ucbrise/MerkleSquare/grpcint"
)

// GetEpochUpdate implements server-side logic for client requesting epoch
// update from the auditor. The auditor periodically queries the server and
// maintains the latest checkpoint, so when client requests the latest
// checkpoint the auditor can simply return the cached checkpoint.
func (a *Auditor) GetEpochUpdate(ctx context.Context,
	req *grpcint.GetEpochUpdateRequest) (*grpcint.GetEpochUpdateResponse, error) {

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &grpcint.GetEpochUpdateResponse{
		CkPoint: a.Checkpoint,
	}, nil
}
