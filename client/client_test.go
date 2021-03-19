package client

import (
	"context"
	"errors"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ucbrise/MerkleSquare/constants"

	"github.com/immesys/bw2/crypto"
)

const ServerAddr = "localhost" + constants.ServerPort

const AuditorAddr = "localhost" + constants.AuditorPort
const VerifierAddr = "localhost" + constants.VerifierPort

var symbols = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randString(n int) string {
	res := make([]byte, n)
	for i := range res {
		res[i] = symbols[rand.Intn(len(symbols))]
	}
	return string(res)
}

func TestAsynchronousClient(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	ctx := context.Background()

	c, err := NewClient(ServerAddr, AuditorAddr, VerifierAddr)
	if err != nil {
		t.Error(errors.New("Failed to start client: " + err.Error()))
	}

	aliceUsername := []byte("alice" + randString(20))

	masterSK, masterVK := crypto.GenerateKeypair()
	_, aliceVK1 := crypto.GenerateKeypair()

	_, err = c.Register(ctx, aliceUsername, masterSK, masterVK)
	if err != nil {
		t.Error(errors.New("Failed to register first user: " + err.Error()))
	}
	_, _, err = c.Append(ctx, aliceUsername, aliceVK1)
	if err != nil {
		t.Error(errors.New("Failed to append alice's PK: " + err.Error()))
	}

	time.Sleep(time.Second * 2)

	key, _, err := c.LookUpMK(ctx, aliceUsername)
	if err != nil {
		t.Error(errors.New("Failed to look up alice's MK: " + err.Error()))
	}
	if !reflect.DeepEqual(key, masterVK) {
		t.Error(errors.New("Master key mismatch"))
	}

	key, _, err = c.LookUpPK(ctx, aliceUsername)
	if err != nil {
		t.Error(errors.New("Failed to look up alice's PK: " + err.Error()))
	}
	if !reflect.DeepEqual(key, aliceVK1) {
		t.Error(errors.New("Public key mismatch"))
	}
}

func TestSynchronousClient(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	ctx := context.Background()

	c, err := NewClient(ServerAddr, AuditorAddr, "")
	if err != nil {
		t.Error(errors.New("Failed to start client: " + err.Error()))
	}

	aliceUsername := []byte("alice" + randString(20))

	masterSK, masterVK := crypto.GenerateKeypair()
	_, aliceVK1 := crypto.GenerateKeypair()

	_, err = c.Register(ctx, aliceUsername, masterSK, masterVK)
	if err != nil {
		t.Error(errors.New("Failed to register first user: " + err.Error()))
	}
	_, _, err = c.Append(ctx, aliceUsername, aliceVK1)
	if err != nil {
		t.Error(errors.New("Failed to append alice's PK: " + err.Error()))
	}

	time.Sleep(time.Second * 2)

	key, _, err := c.LookUpMKVerify(ctx, aliceUsername)
	if err != nil {
		t.Error(errors.New("Failed to look up alice's MK: " + err.Error()))
	}
	if !reflect.DeepEqual(key, masterVK) {
		t.Error(errors.New("Master key mismatch"))
	}

	key, _, err = c.LookUpPKVerify(ctx, aliceUsername)
	if err != nil {
		t.Error(errors.New("Failed to look up alice's PK: " + err.Error()))
	}
	if !reflect.DeepEqual(key, aliceVK1) {
		t.Error(errors.New("Public key mismatch"))
	}
}
