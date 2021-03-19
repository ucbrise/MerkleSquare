package main

import (
	"log"
	"net"
	"runtime"

	"github.com/ucbrise/MerkleSquare/constants"
	"github.com/ucbrise/MerkleSquare/grpcint"
	"github.com/ucbrise/MerkleSquare/verifier/verifierd"

	"google.golang.org/grpc"
)

const ServerPort = constants.ServerPort
const AuditorPort = constants.AuditorPort
const VerifierPort = constants.VerifierPort
const VerifyCycleDuration = constants.VerifyCycleDuration

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	serv, err := verifierd.NewVerifier("localhost"+ServerPort,
		"localhost"+AuditorPort, VerifyCycleDuration)
	if err != nil {
		panic(err)
	}

	listenSocket, err := net.Listen("tcp", VerifierPort)
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	grpcint.RegisterVerifierServer(s, serv)

	if err = s.Serve(listenSocket); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
