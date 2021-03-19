package main

import (
	"log"
	"net"
	"runtime"
	"time"

	"github.com/ucbrise/MerkleSquare/auditor/auditorsrv"
	"github.com/ucbrise/MerkleSquare/constants"
	"github.com/ucbrise/MerkleSquare/grpcint"
	"google.golang.org/grpc"
)

// AuditorPort is the port on which a auditor listens for
// incoming connections.
const ServerPort = constants.ServerPort
const AuditorPort = constants.AuditorPort

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	serv, err := auditorsrv.NewAuditor("localhost"+ServerPort, time.Second)
	if err != nil {
		panic(err)
	}

	listenSocket, err := net.Listen("tcp", AuditorPort)
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	grpcint.RegisterAuditorServer(s, serv)

	if err = s.Serve(listenSocket); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
