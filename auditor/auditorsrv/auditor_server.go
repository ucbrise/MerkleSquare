// Package auditorsrv contains server side implementations for auditor API.
package auditorsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/ucbrise/MerkleSquare/core"
	"github.com/ucbrise/MerkleSquare/grpcint"
	"github.com/ucbrise/MerkleSquare/merkleserver/merkleclt"
)

type Auditor struct {
	merkleClient merkleclt.Client

	epochs     uint64
	Checkpoint *grpcint.CheckPoint

	queryDuration time.Duration
	stopper       chan struct{}
}

func NewAuditor(serverAddr string, queryDuration time.Duration) (
	*Auditor, error) {
	Auditor := &Auditor{
		queryDuration: queryDuration,
		stopper:       make(chan struct{}),
	}
	var err error
	Auditor.merkleClient, err = merkleclt.NewMerkleClient(serverAddr)
	if err != nil {
		return nil, err
	}
	if queryDuration != 0 {
		go Auditor.QueryLoop(time.Unix(0, time.Now().Add(queryDuration).UnixNano()))
	}

	return Auditor, nil
}

func (a *Auditor) QueryLoop(firstQueryTime time.Time) {
	firstQueryDuration := firstQueryTime.Sub(time.Now())
	firstQueryTimer := time.NewTimer(firstQueryDuration)
	var queryTicker *time.Ticker
	until := firstQueryTimer.C
queryLoop:
	for {
		select {
		case <-until:
			//NOTE: Debug
			fmt.Println("Querying Auditor.", time.Now())
			if firstQueryTimer != nil {
				firstQueryTimer.Stop()
				firstQueryTimer = nil
				queryTicker = time.NewTicker(a.queryDuration)
				until = queryTicker.C
			}
			a.QueryServer()

		case <-a.stopper:
			fmt.Println("Stopping query loop!")
			break queryLoop
		}
	}
	if firstQueryTimer != nil {
		firstQueryTimer.Stop()
	}
	if queryTicker != nil {
		queryTicker.Stop()
	}
}

// QueryServer queries server for new checkpoint and an extension proof,
// verifies the extension proof and caches the new checkpoint.
func (a *Auditor) QueryServer() {
	response, err := a.queryServer()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	proven := a.isExtensionProofValid(response)
	if !proven {
		fmt.Printf("Could not prove epoch %v is an extension of epoch %v\n",
			response.CkPoint.GetEpoch(), a.Checkpoint.GetEpoch())
	}

	a.Checkpoint = response.CkPoint
}

// QueryServerForSize queries server for new checkpoint and an extension proof,
// verifies the proof and returns the size of the response returned by the server.
// proof. This function is used for tests measuring size of the message.
func (a *Auditor) QueryServerForSize() int {
	response, err := a.queryServer()
	if err != nil {
		fmt.Printf("%v\n", err)
		return 0
	}
	proven := a.isExtensionProofValid(response)
	if !proven {
		fmt.Printf("Could not prove epoch %v is an extension of epoch %v\n",
			response.CkPoint.GetEpoch(), a.Checkpoint.GetEpoch())
	}

	return proto.Size(response)
}

func (a *Auditor) queryServer() (*grpcint.GetNewCheckPointResponse, error) {
	checkpointRequest := &grpcint.GetNewCheckPointRequest{
		OldSize: a.Checkpoint.GetNumLeaves(),
	}
	response, err := a.merkleClient.GetNewCheckPoint(
		context.Background(), checkpointRequest)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (a *Auditor) isExtensionProofValid(
	response *grpcint.GetNewCheckPointResponse) bool {
	var oldDigest = new(core.Digest)
	var newDigest = new(core.Digest)
	var extensionProof = new(core.MerkleExtensionProof)

	marshaledOldDigest := a.Checkpoint.GetMarshaledDigest()
	json.Unmarshal(marshaledOldDigest, &oldDigest)

	marshaledNewDigest := response.CkPoint.GetMarshaledDigest()
	json.Unmarshal(marshaledNewDigest, &newDigest)

	marshaledProof := response.Proof
	json.Unmarshal(marshaledProof, &extensionProof)

	return core.VerifyExtensionProof(oldDigest, newDigest, extensionProof)
}

// Stop ends the epoch loop. This is useful if you need to free all resources
// associated with a Auditor.
func (a *Auditor) Stop() {
	close(a.stopper)
}
