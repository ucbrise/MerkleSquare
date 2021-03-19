package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"

	crypto "github.com/ucbrise/MerkleSquare/lib/crypto"
)

// MerkleSquare instance
type MerkleSquare struct {
	Roots []MerkleNode
	root  MerkleNode
	next  MerkleNode
	Size  uint32
	depth uint32
}

// MerkleExistenceProof contains an existence proof for a particular LeafNode
type MerkleExistenceProof struct {
	Siblings     []Sibling
	PrefixProofs []MembershipProof
}

// MerkleExtensionProof contains an extension proof for a given digest
type MerkleExtensionProof struct {
	Siblings     []Sibling
	PrefixHashes [][]byte
}

// MKProof contains a proof for a Master Key
type MKProof struct {
	NonMembershipProofs []NonMembershipProof
	MembershipProof     MembershipProof
	ChildHashes         [][]byte
	LeafHash            LeafHash
	OtherHashes         []KeyHash
}

// LatestPKProof contains a proof for the most recent public key
type LatestPKProof struct {
	NonMembershipProofs []NonMembershipProof
	MembershipProof     MembershipProof
	ChildHashes         [][]byte
	LeafHash            LeafHash
	OtherHashes         []KeyHash
}

// NonExistenceProof for proving MSK is first
type NonExistenceProof struct {
	NonMembershipProofs []NonMembershipProof
	ChildHashes         [][]byte
	ExtensionProof      MerkleExtensionProof
	LeafHash            LeafHash
}

// BatchedLookupProof for proving lookups in batch
type BatchedLookupProof struct {
	MembershipProofs    []MembershipProof
	NonMemberShipProofs []NonMembershipProof
	OtherHashes         []KeyHash
	ChildHashes         [][]byte
	LeafHash            LeafHash
	MemProofIndeces     []uint32
}

// Digest struct for snapshots of the current state of MerkleSquare
type Digest struct {
	Roots [][]byte
	Size  uint32
}

// Sibling struct for proofs
type Sibling struct {
	Hash []byte
}

// LeafHash struct for proofs
type LeafHash struct {
	NodeContentHash []byte
	Prefix          []byte
}

// KeyHash struct for existence proof verification
type KeyHash struct {
	Hash []byte
	Pos  uint32
}

//*******************************
// CORE METHODS
//*******************************

// Append a new entry to the MerkleSquare object
func (m *MerkleSquare) Append(key []byte, value []byte, signature []byte) {
	if m.isFull() {
		return // throw error?
	}
	node := m.next.(*LeafNode)
	node.completeLeaf(key, value, signature, m.Size)
	m.appendToPrefixTrees(node, node.getPrefix(), node.getContentHash(), m.Size)
	m.Size++

	p := m.next

	for p.isRightChild() {
		p = p.getParent()
		p.complete()
		m.pop()
	}

	m.addRoot(p)

	// check to see if tree is full
	if m.isFull() {
		return
	}
	_ = p.getParent().createRightChild()
	p = p.getParent().getRightChild()

	for p.getDepth() > 0 {
		_ = p.createLeftChild()
		p = p.getLeftChild()
	}

	m.next = p
}

// GenerateExistenceProof generates an existence proof for a given key/height pair
func (m *MerkleSquare) GenerateExistenceProof(key []byte, pos uint32, height uint32, oldSize uint32) *MerkleExistenceProof {

	node := m.getNode(0, pos)
	siblings := []Sibling{}
	prefixProofs := []MembershipProof{}
	treeDepth := GetOldDepth(pos, oldSize)
	prefix := makePrefixFromKey(key)

	for node.getDepth() != treeDepth { // only thing that needs to change is m.depth to the depth of the tree that the key belongs to in new Size

		if height > 0 {
			height = height - 1
		} else {

			prefixTree := node.getParent().getPrefixTree()
			proof, _ := prefixTree.generateMembershipProof(prefix)
			prefixProofs = append(prefixProofs, *proof)

			sibling := node.getSibling()
			siblings = append(siblings, sibling)
		}

		node = node.getParent()
	}

	return &MerkleExistenceProof{
		Siblings:     siblings,
		PrefixProofs: prefixProofs,
	}
}

// GenerateExtensionProof generates an extension proof for a given digest
func (m *MerkleSquare) GenerateExtensionProof(oldSize uint32, requestedSize uint32) *MerkleExtensionProof {

	roots := m.getOldRoots(requestedSize)
	oldDigestRoots := m.getOldRoots(oldSize)
	res := &MerkleExtensionProof{}

	for i, root := range oldDigestRoots {
		if !bytes.Equal(root.getHash(), roots[i].getHash()) { // if we want size param: switch m.roots for getRoots()

			lastNode := oldDigestRoots[len(oldDigestRoots)-1]

			generateExtensionProof(lastNode, res, roots[i].getDepth()) // if we want size param: need to pass in correct depth for the tree that the last element/root belongs to (olddigest.size) in proof version?
			break
		}
	}

	return res
}

func generateExtensionProof(node MerkleNode, proof *MerkleExtensionProof, depth uint32) {

	siblings := []Sibling{}
	prefixHashes := [][]byte{}

	for node.getDepth() != depth { // if we want size param: remove isComplete() and pass in correct depth

		if !node.isRightChild() {
			sibling := node.getSibling()
			siblings = append(siblings, sibling)
		}
		prefixHashes = append(prefixHashes, node.getParent().getPrefixTree().getHash())

		node = node.getParent()
	}

	proof.Siblings = siblings
	proof.PrefixHashes = prefixHashes
}

// ProveFirst generates a MKProof for a master key
func (m *MerkleSquare) ProveFirst(key []byte, MK []byte, pos uint32, oldSize uint32) *MKProof {

	index := getRootIndex(pos, oldSize)
	roots := m.getOldRoots(oldSize)
	prefix := makePrefixFromKey(key)

	leafHash := LeafHash{}
	nonMembershipProofs := []NonMembershipProof{}
	childHashes := [][]byte{}

	var memProofResult *MembershipProof
	var membershipProof MembershipProof
	var hashes []KeyHash
	for i, root := range roots {

		if root.isLeafNode() && i == int(index) {
			leafHash.NodeContentHash = root.getContentHash()
			break
		} else if root.isLeafNode() {
			break
		}

		prefixTree := root.getPrefixTree()

		childHashes = append(childHashes, root.getLeftChild().getHash())
		childHashes = append(childHashes, root.getRightChild().getHash())

		if i == int(index) {
			memProofResult, hashes = prefixTree.generateMembershipProof(prefix)
			hashes = filterOutKeyHash(hashes, pos)
			membershipProof = *memProofResult
			break
		}

		nonMembershipProofs = append(nonMembershipProofs, *prefixTree.generateNonMembershipProof(prefix))
	}

	return &MKProof{
		NonMembershipProofs: nonMembershipProofs,
		MembershipProof:     membershipProof,
		ChildHashes:         childHashes,
		LeafHash:            leafHash,
		OtherHashes:         hashes,
	}
}

// ProveLatest generates a LatestPKProof for a given PK
func (m *MerkleSquare) ProveLatest(key []byte, PK []byte, pos uint32, oldSize uint32) *LatestPKProof {

	index := getRootIndex(pos, oldSize)
	roots := m.getOldRoots(oldSize)
	prefix := makePrefixFromKey(key)

	childHashes := [][]byte{}
	nonMembershipProofs := []NonMembershipProof{}
	leafHash := LeafHash{}

	var memProofResult *MembershipProof
	var membershipProof MembershipProof
	var hashes []KeyHash
	for i := index; int(i) < len(roots); i++ { // change to getRoots()

		root := roots[i]

		if root.isLeafNode() {
			leafHash.NodeContentHash = root.getContentHash()

			if i != index {
				leafHash.Prefix = root.getPrefix()
			}
			break
		}

		prefixTree := root.getPrefixTree()
		childHashes = append(childHashes, root.getLeftChild().getHash())
		childHashes = append(childHashes, root.getRightChild().getHash())

		if i == index {
			memProofResult, hashes = prefixTree.generateMembershipProof(prefix)
			hashes = filterOutKeyHash(hashes, pos)
			membershipProof = *memProofResult
		} else {
			nonMembershipProofs = append(nonMembershipProofs, *prefixTree.generateNonMembershipProof(prefix))
		}
	}

	return &LatestPKProof{
		NonMembershipProofs: nonMembershipProofs,
		MembershipProof:     membershipProof,
		ChildHashes:         childHashes,
		LeafHash:            leafHash,
		OtherHashes:         hashes,
	}
}

// ProveNonexistence provides a nonexistence proof for a given MSK/key
func (m *MerkleSquare) ProveNonexistence(key []byte, mskPos uint32, currSize uint32) *NonExistenceProof {

	prefix := makePrefixFromKey(key)
	oldRoots := m.getOldRoots(mskPos)

	nonMemberShipProofs := []NonMembershipProof{}
	childHashes := [][]byte{}
	var leafHash LeafHash

	for _, root := range oldRoots {
		if root.isLeafNode() {
			leafHash = LeafHash{
				Prefix:          root.getPrefix(),
				NodeContentHash: root.getContentHash(),
			}
			break
		}

		childHashes = append(childHashes, root.getLeftChild().getHash())
		childHashes = append(childHashes, root.getRightChild().getHash())

		prefixTree := root.getPrefixTree()
		nonMemberShipProofs = append(nonMemberShipProofs, *prefixTree.generateNonMembershipProof(prefix))
	}

	extensionProof := m.GenerateExtensionProof(mskPos, currSize)

	return &NonExistenceProof{
		NonMembershipProofs: nonMemberShipProofs,
		ChildHashes:         childHashes,
		ExtensionProof:      *extensionProof,
		LeafHash:            leafHash,
	}
}

// GenerateBatchedLookupProof provides a batched lookup proof for a particular prefix and key positions
func (m *MerkleSquare) GenerateBatchedLookupProof(startSize uint32, endSize uint32, key []byte, keyPositions []uint32) (*BatchedLookupProof, error) {

	prefix := makePrefixFromKey(key)
	oldRoots := m.getOldRoots(endSize)
	nextRoot := getRootIndex(startSize, endSize)

	membershipProofs := []MembershipProof{}
	nonMembershipProofs := []NonMembershipProof{}
	otherHashes := []KeyHash{}
	childHashes := [][]byte{}
	leafHash := LeafHash{}
	memProofIndeces := []uint32{}

	for j := nextRoot; j < len(oldRoots); j++ {

		root := oldRoots[j]
		if root.isLeafNode() {
			if !bytes.Equal(root.getPrefix(), prefix) {
				leafHash.Prefix = root.getPrefix()
				leafHash.NodeContentHash = root.getContentHash()
			} else if len(keyPositions) == 0 || len(keyPositions) > 0 && root.getShift() != keyPositions[len(keyPositions)-1] {
				lastKeyHash := KeyHash{
					Hash: root.getContentHash(),
					Pos:  root.getShift(),
				}
				otherHashes = append(otherHashes, lastKeyHash)
			}
			break
		}

		prefixTree := root.getPrefixTree()
		nonMemProof := prefixTree.generateNonMembershipProof(prefix)
		childHashes = append(childHashes, root.getLeftChild().getHash(), root.getRightChild().getHash())

		if nonMemProof == nil {

			memProof, hashes := prefixTree.generateMembershipProof(prefix)

			hashes = filterOutKeyHash(hashes, keyPositions...)
			membershipProofs = append(membershipProofs, *memProof)
			otherHashes = append(otherHashes, hashes...)
			memProofIndeces = append(memProofIndeces, uint32(j))

		} else {
			nonMembershipProofs = append(nonMembershipProofs, *nonMemProof)
		}

	}

	return &BatchedLookupProof{
		MembershipProofs:    membershipProofs,
		NonMemberShipProofs: nonMembershipProofs,
		OtherHashes:         otherHashes,
		ChildHashes:         childHashes,
		LeafHash:            leafHash,
		MemProofIndeces:     memProofIndeces,
	}, nil
}

//*******************************
// VERIFICATION METHODS
//*******************************

// VerifyExistenceProof verifies an ExistenceProof
func VerifyExistenceProof(oldDigest *Digest, nodeHash []byte, key []byte, pos uint32, height uint32, proof *MerkleExistenceProof, oldKeys []KeyHash) (bool, []byte, uint32) {

	prefix := makePrefixFromKey(key)
	rootIndex := getRootIndex(pos, oldDigest.Size)
	shift := calculateParentShift(pos, height)
	rootHash := oldDigest.Roots[rootIndex]
	hash := nodeHash

	var left, right uint32
	if height != 0 {
		left, right = calculateLeftRightRange(shift/2, height+1)
	} else {
		left, right = calculateLeftRightRange(shift, height)
	}

	for i, sib := range proof.Siblings {

		otherHashes := computeMemberKeys(oldDigest.Size, oldKeys, left, right)
		prefixHash := computeRootHashMembership(prefix, &proof.PrefixProofs[i], otherHashes)

		if isRight(shift) {
			hash = crypto.Hash(sib.Hash, hash, prefixHash)
		} else {
			hash = crypto.Hash(hash, sib.Hash, prefixHash)
		}

		shift = shift / 2
		diff := right - left + 1
		if isRight(shift) && left != 0 {
			left = left - diff
		} else if right != oldDigest.Size-1 {
			right = right + diff
		}
	}

	return bytes.Equal(rootHash, hash), hash, GetOldDepth(pos, oldDigest.Size)
}

// VerifyExtensionProof verifies an ExtensionProof
func VerifyExtensionProof(oldDigest *Digest, newDigest *Digest, proof *MerkleExtensionProof) bool {

	for i, oldRoot := range oldDigest.Roots {
		if bytes.Equal(oldRoot, newDigest.Roots[i]) {
			continue
		}

		p := len(oldDigest.Roots) - 2
		hash := oldDigest.Roots[p+1]

		lastRootDepth := GetOldDepth(oldDigest.Size-1, oldDigest.Size)
		newRootDepth := GetOldDepth(oldDigest.Size-1, newDigest.Size)
		shift := oldDigest.Size - 1
		siblingIndex := 0
		prefixIndex := 0

		for j := 0; uint32(j) < newRootDepth; j++ {
			if uint32(j) >= lastRootDepth && isRight(shift) {
				hash = crypto.Hash(oldDigest.Roots[p], hash, proof.PrefixHashes[prefixIndex])
				prefixIndex++
				p = p - 1
			} else if uint32(j) >= lastRootDepth {
				hash = crypto.Hash(hash, proof.Siblings[siblingIndex].Hash, proof.PrefixHashes[prefixIndex])
				prefixIndex++
				siblingIndex++
			}

			shift = shift / 2
		}

		return bytes.Equal(hash, newDigest.Roots[i])
	}

	return true
}

// VerifyMKProof verifies an MKProof
func VerifyMKProof(digest *Digest, key []byte, value []byte, signature []byte, pos uint32, proof *MKProof) bool {

	childHashes := proof.ChildHashes

	rootIndex := getRootIndex(pos, digest.Size)
	rootDepth := GetOldDepth(pos, digest.Size)
	prefix := makePrefixFromKey(key)

	if len(proof.NonMembershipProofs) != rootIndex {
		return false
	}

	for i, proof := range proof.NonMembershipProofs {
		if !verifySingularNonMembershipProof(digest.Roots[i], proof, childHashes[2*i], childHashes[2*i+1], prefix) {
			return false
		}
	}

	if rootDepth == 0 {
		hash := computeLeafHash(prefix, proof.LeafHash.NodeContentHash)
		return bytes.Equal(hash, digest.Roots[rootIndex])
	}

	otherHashes := AddKeyHash(proof.OtherHashes, key, value, signature, pos)

	return verifySingularMembershipProof(digest.Roots[rootIndex], proof.MembershipProof, childHashes[2*rootIndex], childHashes[2*rootIndex+1], prefix, otherHashes)
}

// VerifyPKProof verifies a LatestPKProof
func VerifyPKProof(digest *Digest, key []byte, value []byte, signature []byte, pos uint32, proof *LatestPKProof) bool {

	childHashes := proof.ChildHashes
	rootIndex := getRootIndex(pos, digest.Size)
	rootDepth := GetOldDepth(pos, digest.Size)
	lastRootDepth := GetOldDepth(digest.Size-1, digest.Size)
	prefix := makePrefixFromKey(key)

	if rootDepth == 0 {
		contentHash := ComputeContentHash(key, value, signature, pos)
		hash := computeLeafHash(prefix, contentHash)
		return bytes.Equal(hash, digest.Roots[rootIndex])
	}
	otherHashes := AddKeyHash(proof.OtherHashes, key, value, signature, pos)
	if !verifySingularMembershipProof(digest.Roots[rootIndex], proof.MembershipProof, childHashes[0], childHashes[1], prefix, otherHashes) {
		return false
	}

	if len(proof.NonMembershipProofs) < len(digest.Roots)-rootIndex-2 {
		return false
	}

	for i := rootIndex + 1; i < len(digest.Roots); i++ {

		if i == len(digest.Roots)-1 && lastRootDepth == 0 {
			hash := computeLeafHash(proof.LeafHash.Prefix, proof.LeafHash.NodeContentHash)
			return bytes.Equal(hash, digest.Roots[i]) && !bytes.Equal(proof.LeafHash.Prefix, prefix)
		}

		p := i - rootIndex
		if !verifySingularNonMembershipProof(digest.Roots[i], proof.NonMembershipProofs[p-1], childHashes[2*p], childHashes[2*p+1], prefix) {
			return false
		}
	}

	return true
}

// VerifyNonexistenceProof verifies a NonExistenceProof
func VerifyNonexistenceProof(key []byte, mskPos uint32, newDigest *Digest, proof *NonExistenceProof) bool {

	prefix := makePrefixFromKey(key)
	oldRootHashes := [][]byte{}

	for i, nonMembershipProof := range proof.NonMembershipProofs {
		prefixHash := computeRootHashNonMembership(prefix, &nonMembershipProof)
		rootHash := crypto.Hash(proof.ChildHashes[2*i], proof.ChildHashes[2*i+1], prefixHash)

		oldRootHashes = append(oldRootHashes, rootHash)
	}

	if mskPos != 0 && GetOldDepth(mskPos-1, mskPos) == 0 {
		if bytes.Equal(prefix, proof.LeafHash.Prefix) {
			return false
		}

		rootHash := crypto.Hash(proof.LeafHash.Prefix, proof.LeafHash.NodeContentHash)
		oldRootHashes = append(oldRootHashes, rootHash)
	}

	oldDigest := &Digest{
		Roots: oldRootHashes,
		Size:  mskPos,
	}

	return VerifyExtensionProof(oldDigest, newDigest, &proof.ExtensionProof)
}

// VerifyBatchedLookupProof verifies a BatchedLookupProof
func VerifyBatchedLookupProof(startSize uint32, key []byte, keyHashes []KeyHash, digest *Digest, proof *BatchedLookupProof) (bool, error) {

	nextRoot := getRootIndex(startSize, digest.Size)
	prefix := makePrefixFromKey(key)
	if !checkKeyHashes(keyHashes, proof.OtherHashes) {
		return false, fmt.Errorf("Key occurs between lookup range")
	}

	memProofCounter := 0
	nonMemProofCounter := 0

	keyHashes = combineKeyHashes(keyHashes, proof.OtherHashes)

	for j := nextRoot; j < len(digest.Roots); j++ {

		rootHash := digest.Roots[j]

		// handle leaf case
		if j == len(digest.Roots)-1 && GetOldDepth(digest.Size-1, digest.Size) == 0 {

			// if NodeContentHash is != nil, then we check case where it is not owned by prefix
			if proof.LeafHash.NodeContentHash != nil {
				// case where doesn't equal
				hash := computeLeafHash(proof.LeafHash.Prefix, proof.LeafHash.NodeContentHash)
				if bytes.Equal(proof.LeafHash.Prefix, prefix) || !bytes.Equal(rootHash, hash) {
					return false, fmt.Errorf("Unable to verify nonmembership for leaf root %d", j)
				}
			} else {
				// otherwise, check ownership of prefix; ContentHash should be last element in keyHashes
				hash := computeLeafHash(prefix, keyHashes[len(keyHashes)-1].Hash)

				if !bytes.Equal(rootHash, hash) {
					return false, fmt.Errorf("Unable to verify membership for leaf root %d", j)
				}
			}
			break
		}

		if memProofCounter < len(proof.MemProofIndeces) && uint32(j) == proof.MemProofIndeces[memProofCounter] {
			memProof := proof.MembershipProofs[memProofCounter]
			left, right := getRootRange(uint32(j), digest.Size)
			otherHashes := computeMemberKeys(digest.Size, keyHashes, left, right)

			if !verifySingularMembershipProof(rootHash, memProof, proof.ChildHashes[2*(j-nextRoot)], proof.ChildHashes[2*(j-nextRoot)+1], prefix, otherHashes) {
				return false, fmt.Errorf("Unable to verify membership proof for root %d", j)
			}

			memProofCounter++
		} else {
			nonMemProof := proof.NonMemberShipProofs[nonMemProofCounter]
			if !verifySingularNonMembershipProof(rootHash, nonMemProof, proof.ChildHashes[2*(j-nextRoot)], proof.ChildHashes[2*(j-nextRoot)+1], prefix) {
				return false, fmt.Errorf("Unable to verify NonMembership proof for root %d", j)
			}
			nonMemProofCounter++
		}

	}
	return true, nil

}

//*******************************
// HELPER METHODS
//*******************************

func verifySingularMembershipProof(rootHash []byte, proof MembershipProof, leftChildHash []byte, rightChildHash []byte, prefix []byte, otherHashes []KeyHash) bool {
	prefixHash := computeRootHashMembership(prefix, &proof, otherHashes)
	hash := crypto.Hash(leftChildHash, rightChildHash, prefixHash)

	return bytes.Equal(hash, rootHash)
}

func verifySingularNonMembershipProof(rootHash []byte, proof NonMembershipProof, leftChildHash []byte, rightChildHash []byte, prefix []byte) bool {

	prefixHash := computeRootHashNonMembership(prefix, &proof)
	hash := crypto.Hash(leftChildHash, rightChildHash, prefixHash)

	return bytes.Equal(hash, rootHash)

}

// Given a previous tree Size + an array of KeyHash structs, compute which elements of the array fall under the
// desired prefix tree for computing the prefix hash.
func computeMemberKeys(oldSize uint32, oldKeys []KeyHash, left uint32, right uint32) []KeyHash {
	i := 0
	j := len(oldKeys) - 1

	for i < len(oldKeys) && oldKeys[i].Pos < left {
		i++
	}

	for j >= 0 && oldKeys[j].Pos > right {
		j = j - 1
	}

	memberKeys := oldKeys[i : j+1]
	res := []KeyHash{}

	for _, key := range memberKeys {
		res = append(res, key)
	}

	return res
}

// ComputeLeafNodeHash generates the hash for a leaf node
func ComputeLeafNodeHash(key []byte, value []byte, signature []byte, pos uint32) []byte {
	return computeLeafHash(makePrefixFromKey(key), ComputeContentHash(key, value, signature, pos))
}

func computeLeafHash(prefix []byte, nodeContentHash []byte) []byte {
	return crypto.Hash(prefix, nodeContentHash)
}

func ComputeContentHash(key []byte, value []byte, signature []byte, pos uint32) []byte {
	posAsByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(posAsByte, pos)

	contentHash := crypto.Hash(key, value, signature, posAsByte)

	return contentHash
}

func filterOutKeyHash(otherHashes []KeyHash, pos ...uint32) []KeyHash {

	res := []KeyHash{}

	for i, j := 0, 0; i < len(otherHashes); {
		if j >= len(pos) {
			res = append(res, otherHashes[i:]...)
			break
		} else if otherHashes[i].Pos < pos[j] {
			res = append(res, otherHashes[i])
			i++
		} else if otherHashes[i].Pos > pos[j] {
			j++
		} else {
			i++
		}
	}

	return res
}

func checkKeyHashes(lookupHashes []KeyHash, otherHashes []KeyHash) bool {

	for i, j := 0, 0; i < len(lookupHashes)-1 && j < len(otherHashes); {

		if otherHashes[j].Pos < lookupHashes[i].Pos {
			j++
		} else if otherHashes[j].Pos < lookupHashes[i+1].Pos {
			return false
		} else {
			i += 2
		}
	}

	return true
}

// AddKeyHash adds a keyHash to an array of otherHashes
func AddKeyHash(otherHashes []KeyHash, key []byte, value []byte, signature []byte, pos uint32) []KeyHash {

	contentHash := ComputeContentHash(key, value, signature, pos)

	computedValue := KeyHash{
		Hash: contentHash,
		Pos:  pos,
	}

	for i, elem := range otherHashes {
		if pos < elem.Pos {

			otherHashes = append(otherHashes, KeyHash{})
			copy(otherHashes[i+1:], otherHashes[i:])
			otherHashes[i] = computedValue

			return otherHashes
		}
	}
	otherHashes = append(otherHashes, computedValue)

	return otherHashes
}

// GetOldDepth given a position and size for an old forest, returns the depth of the tree pos belongs to
func GetOldDepth(pos uint32, size uint32) uint32 {

	index := getRootIndex(pos, size)
	leadingZeros := bits.LeadingZeros32(size)
	mask := 1 << (31 - leadingZeros)

	for index > 0 {

		index = index - 1
		mask = mask >> 1

		for bits.OnesCount(uint(mask&int(size))) == 0 {
			mask = mask >> 1
		}
	}

	return uint32(bits.TrailingZeros(uint(mask)))
}

// Gets Roots of MerkleSquare when it only contained oldSize keys
func (m *MerkleSquare) getOldRoots(oldSize uint32) []MerkleNode {
	Roots := []MerkleNode{}
	var totalKeys uint32 = 0
	var mask uint32 = 1 << m.depth

	for mask > 0 {

		if bits.OnesCount32(mask&oldSize) == 1 {

			depth := bits.TrailingZeros32(mask)
			shift := totalKeys >> bits.TrailingZeros32(mask)

			Roots = append(Roots, m.getNode(uint32(depth), shift))

			totalKeys += mask
		}
		mask = mask >> 1
	}

	return Roots
}

// Appends a value to all prefix trees up to the root (even for ghost nodes)
func (m *MerkleSquare) appendToPrefixTrees(node MerkleNode, prefix []byte, valueHash []byte, pos uint32) {

	for node.getDepth() != m.depth {
		node = node.getParent()
		node.getPrefixTree().PrefixAppend(prefix, valueHash, pos)
	}
}

// Returns the root index that pos belongs to given the forest Size
func getRootIndex(pos uint32, Size uint32) int {

	xor := pos ^ Size
	leadingZeros := bits.LeadingZeros32(xor)

	forestSize := int(Size) >> (32 - leadingZeros)

	return bits.OnesCount32(uint32(forestSize))
}

func getRange(pos uint32, size uint32) (uint32, uint32) {

	parentHeight := GetOldDepth(pos, size)
	parentShift := calculateParentShift(pos, parentHeight)

	left, right := calculateLeftRightRange(parentShift, parentHeight)

	return left, right
}

func getRootRange(rootIndex uint32, size uint32) (uint32, uint32) {

	mask := uint32(1)
	rootLength := uint32(bits.OnesCount32(size))

	for i := uint32(0); i < rootLength-rootIndex; i++ {
		for bits.OnesCount32(mask&size) != 1 {
			mask = mask << 1
		}

		if i != rootLength-rootIndex-1 {
			size = size ^ mask
			mask = mask << 1
		}
	}

	return size - mask, size - 1
}

func calculateLeftRightRange(shift uint32, height uint32) (uint32, uint32) {

	if height == 0 {
		if isRight(shift) {
			return shift - 1, shift
		}

		return shift, shift + 1
	}

	left, right := shift, shift

	for ; height > 0; height-- {
		right = 2*right + 1
		left = 2 * left
	}

	return left, right
}

func calculateParentShift(pos uint32, parentHeight uint32) uint32 {

	shift := pos
	for j := 0; uint32(j) < parentHeight; j++ {
		shift = shift / 2
	}

	return shift
}

func combineKeyHashes(keyHashes0 []KeyHash, keyHashes1 []KeyHash) []KeyHash {

	if len(keyHashes0) == 0 {
		return keyHashes1
	} else if len(keyHashes1) == 0 {
		return keyHashes0
	}

	res := []KeyHash{}
	i, j := 0, 0

	for i < len(keyHashes0) && j < len(keyHashes1) {
		if keyHashes0[i].Pos < keyHashes1[j].Pos {
			res = append(res, keyHashes0[i])
			i++
		} else {
			res = append(res, keyHashes1[j])
			j++
		}
	}

	if i == len(keyHashes0) {
		res = append(res, keyHashes1[j:]...)
	} else {
		res = append(res, keyHashes0[i:]...)
	}

	return res
}

// Gets a MerkleNode from an index
func (m *MerkleSquare) getNodeFromIndex(index index) MerkleNode {

	node := m.root

	for node.getDepth() != index.depth {

		if isRightOf(node.getIndex(), index) {
			node = node.getRightChild()
		} else {
			node = node.getLeftChild()
		}

	}

	return node
}

// returns true iff index2 is to the right of index1
func isRightOf(index1 index, index2 index) bool {

	heightDiff := index1.depth - index2.depth

	relativeWidth := uint32(1 << heightDiff)
	startIndex := relativeWidth * index1.shift

	return index2.shift >= startIndex+(relativeWidth>>1)
}

func (m *MerkleSquare) getNode(depth uint32, shift uint32) MerkleNode {
	index := index{
		depth: depth,
		shift: shift,
	}

	return m.getNodeFromIndex(index)
}

// Fetches a leaf node at a given position in the MerkleSquare struct (log n)
func (m *MerkleSquare) getLeafNode(pos uint32) MerkleNode {

	node := m.root

	for node.getDepth() > 0 {
		shift := node.getDepth() - 1

		if pos&(1<<shift)>>shift == 1 {
			node = node.getRightChild()
		} else {
			node = node.getLeftChild()
		}
	}

	return node
}

// GetDigest returns the most recent digest of a MerkleSquare struct
func (m *MerkleSquare) GetDigest() *Digest {
	Roots := [][]byte{}

	for _, root := range m.Roots {
		Roots = append(Roots, root.getHash())
	}

	return &Digest{
		Roots: Roots,
		Size:  m.Size,
	}
}

// GetOldDigest returns a digest of the a MerkleSquare instance
// when it only contained oldSize keys.
func (m *MerkleSquare) GetOldDigest(oldSize uint32) *Digest {
	Roots := [][]byte{}

	for _, root := range m.getOldRoots(oldSize) {
		Roots = append(Roots, root.getHash())
	}

	return &Digest{
		Roots: Roots,
		Size:  oldSize,
	}
}

// Pops an element from the forest and returns it
func (m *MerkleSquare) pop() MerkleNode {

	numTrees := len(m.Roots)
	node := m.Roots[numTrees-1]
	m.Roots = m.Roots[:numTrees-1]

	return node
}

// Adds an element to the forest
func (m *MerkleSquare) addRoot(node MerkleNode) {
	m.Roots = append(m.Roots, node)
}

func (m *MerkleSquare) isFull() bool {
	return m.Size == 1<<m.depth
}

func isRight(shift uint32) bool {
	return shift%2 != 0
}

// NewMerkleSquare is a factory method for constructing MerkleSquare objects
func NewMerkleSquare(depth uint32) *MerkleSquare {
	m := &MerkleSquare{
		Roots: []MerkleNode{},
		Size:  0,
		depth: depth,
	}

	next := createRootNode(depth)
	m.root = next

	for next.getDepth() > 0 {
		_ = next.createLeftChild()
		next = next.getLeftChild()
	}

	m.next = next

	return m
}

// GetMerkleSquareSize returns the # bytes MerkleSquare object requires
func (m *MerkleSquare) GetMerkleSquareSize() int {

	// root + next pointers
	total := pointerSizeInBytes * 2

	// forest root pointers
	for range m.Roots {
		total += pointerSizeInBytes
	}

	// size and depth
	total += binary.Size(m.Size) + binary.Size(m.depth)

	// recursively find tree size
	total += m.root.getSize()

	return total
}
