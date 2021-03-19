<h1 align="center">MerkleSquare</h1>

<p align="center">
    <a href="https://github.com/ucbrise/MerkleSquare/blob/release/LICENSE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
</p>

`MerkleSquare` is a Go library that implements
<p align="center">
<b>Merkle<sup>2</sup>: A Low-Latency Transparency Log System</b>
</p>

This library was initially developed as part of the [Merkle<sup>2</sup>][MerkleSquare] paper, and is released under the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic prototype, and has not received careful code review. This implementation is NOT ready for production use.

## Overview
Transparency logs are designed to help users audit untrusted servers. They are consistent, immutable, and append-only logs: anybody reading the log entries will see the same entries in the same order, nobody can modify data already in the log, and parties can only append new data. Common transparency logs also provide an efficient **dictionary** for key-value pairs stored in the log.

One of their distinctive features is that they combine aspects of blockchains with aspects of traditional centralized hosting.
Like blockchains and ledgers, transparency logs rely on **decentralized verification**, enabling anyone to verify their integrity.
At the same time, they are hosted traditionally by a **central  service provider**, such as Google.
Due to guarantees provided by the log and decentralized verification by third parties, the service provider cannot modify or fork the log without detection.
Additionally, centralized hosting enables these logs to be significantly more efficient than Bitcoin-like blockchains; they provide higher throughput and lower latency while avoiding expensive proof of work or the expensive replication of the ledger state at many users. 

We propose Merkle<sup>2</sup>, a transparency log system that supports both efficient monitoring and low-latency updates. 
To achieve this goal, we construct a new multi-dimensional authenticated data structure that nests two types of Merkle trees, hence the name for our system, **Merkle<sup>2</sup>**. All operations in Merkle<sup>2</sup> are independent of update intervals and are (poly)logarithmic to the number of entries in the log, resulting in efficient monitoring and lookup protocols.

The construction in this library follows the methodology introduced in the [Merkle<sup>2</sup>][MerkleSquare] paper. The library includes the following two ingredients:

* the **Merkle<sup>2</sup> data structure implementation**
* the **Merkle<sup>2</sup> system implementation**


## Directory structure

This repository contains several packages:

* [`lib`](lib): Provides implementations of various crypto and storage helper functions. We use [LevelDB](https://github.com/google/leveldb) as the underlying persistent storage.
* [`grpcint`](grpcint): Provides communication interfaces among server, client, verifier (verification daemon), and auditor.
* [`constants`](constants): Defines several constant parameters used in our library.
* [`auditor`](auditor): Implements the Merkle<sup>2</sup> auditor and client functions to interact with the auditor. The auditor will periodically download digests and proofs from the server.
* [`client`](client): Implements the Merkle<sup>2</sup> client APIs for application users. The client interacts with the server to append, look up and obtain proofs. The client also interacts with the auditor to obtain checkpoints and digests. For each append, the client sends messages to the verifier so that it can monitor on behalf of the owner. For each lookup, the client can choose to check the lookup proof immediately or ask the verifier to check the proof later. See Section II of [Merkle<sup>2</sup>][MerkleSquare] paper for more details.
* [`merkleserver`](merkleserver) Implements the Merkle<sup>2</sup> server and the client functions to interact with the server.
* [`verifier`](verifier) Implements the verification daemon. The verifier will periodically monitor the owner's appends. The verifier can also verify lookup results if the client chooses to verify the response asynchronously.
* [`core`](core): Provides implementations of Merkle<sup>2</sup>'s data structure. It consists of the compressed prefix tree implementation and the chronological tree implementation. Each internal node of the chronological tree is associated with a compressed prefix tree. This package also generates proofs used in Merkle<sup>2</sup>'s protocol.
* [`demo`](demo): Provides codes to run the demo server, auditor, and verifier.

## Build guide
This code has been tested with Go version 1.13.9/1.14.2 on macOS 10.14.6 and Ubuntu 18.04.

The Merkle<sup>2</sup> package relies on the following:
- Go build environment (be careful of the version)
- [OpenSSL](https://github.com/openssl/openssl) for crypto supports
- [GoLevelDB](https://github.com/syndtr/goleveldb) for the Go implementation of LevelDB  
- [bw2crypto](https://github.com/immesys/bw2/tree/dev/crypto) for necessary crypto primitives
- [grpc](https://github.com/grpc/grpc-go#installation) for the Go implementation of gRPC
- [protobuf](https://github.com/golang/protobuf/) for the Go support for Protocol Buffers
- [coniks-go](https://github.com/coniks-sys/coniks-go) for VRFs (VRFs are currently disabled but we have left the interface in place)

To obtain the Merkle<sup>2</sup> package, run the following command:
```console
$ go get github.com/ucbrise/MerkleSquare
```
## Demo
You can run the demo server, auditor, and verifier in the [`demo/server`](demo/server), [`demo/auditor`](demo/auditor), [`demo/verifier`](demo/verifier) directories by running the following command:
```console
$ go run main.go
```

Then, you can test the client functions in the [`client`](client) directory by running the following command:
```console
$ go test -v
```

## License

This library is licensed under either of the following licenses, at your discretion.

 * [Apache License Version 2.0](LICENSE)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

[MerkleSquare]: https://

## Reference paper

[Merkle<sup>2</sup>: A Low-Latency Transparency Log System][MerkleSquare]  
[Yuncong Hu](https://github.com/huyuncong), [Kian Hooshmand](https://github.com/Kian1354), [Harika Kalidhindi](https://github.com/jrharika), [Seung Jin Yang](https://github.com/SeungjinYang), and [Raluca Ada Popa](https://github.com/ralucaada)

IEEE S&P 2021

## Disclaimer
This MerkleSquare library is under active development. The repository may contain experimental features that aren't fully tested.

## Acknowledgements
This research was supported by the NSF CISE Expeditions Award CCF-1730628, NSF Career 1943347, as well as gifts from the Sloan Foundation, Bakar, Okawa, Amazon Web Services, AntGroup, Capital One, Ericsson, Facebook, Futurewei, Google, Intel, Microsoft, Nvidia, Scotiabank, Splunk, and VMware.
