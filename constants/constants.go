package constants

import "time"

const ServerPort = ":49563"
const AuditorPort = ":49564"
const VerifierPort = ":49562"
const EpochDuration = time.Second
const VerifyCycleDuration = time.Second * 5
const MerkleDepth = 31
const pointerSizeInBytes = 8
