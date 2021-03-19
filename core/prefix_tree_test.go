package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	crypto "github.com/ucbrise/MerkleSquare/lib/crypto"
)

const PREFIXVRFSIZE, VALUEHASHSIZE uint32 = 32, 32

func TestPrefixAppendOnce(t *testing.T) {
	tree := NewPrefixTree()
	prefix := makePrefixFromKey([]byte{0b01})
	valueHash := crypto.Hash([]byte{0b1})
	pos := uint32(1)

	tree.PrefixAppend(prefix, valueHash, pos)
	//For example,
	//				root
	//				/
	//			compressed leaf
	leaf := getOnlyChild(tree.root, t)
	if !leaf.isLeafNode() {
		t.Error()
	}
	if !bytes.Equal(makePrefixFromLeaf(leaf, t), prefix) {
		t.Error()
	}
	if !bytes.Equal(leaf.getValues()[0].Hash, valueHash) {
		t.Error()
	}
	if leaf.getValues()[0].Pos != pos {
		t.Error()
	}
}

func TestPrefixAppendTwoKeys(t *testing.T) {
	tree := NewPrefixTree()
	prefix0 := []byte{0b0, 0b1}
	prefix1 := []byte{0b0, 0b0}
	valueHash0 := crypto.Hash([]byte{0b101})
	valueHash1 := crypto.Hash([]byte{0b110})
	pos0 := uint32(31)
	pos1 := uint32(25)

	tree.PrefixAppend(prefix0, valueHash0, pos0)
	tree.PrefixAppend(prefix1, valueHash1, pos1)
	var leafL, leafR prefixNode

	if prefix0[0] == prefix1[0] {
		//For example,
		//				root
		//				/
		//			compressed
		//			 /		  \
		//	compressed leaf	  compressed leaf
		sharedChild := getOnlyChild(tree.root, t)
		leafL = sharedChild.getLeftChild()
		if leafL == nil || !leafL.isLeafNode() {
			t.Error()
		}
		leafR = sharedChild.getRightChild()
		if leafR == nil || !leafR.isLeafNode() {
			t.Error()
		}

	} else {
		//looks like,
		//			     root
		//		         /	\
		//compressed leaf	 compressed leaf
		leafL = tree.root.getLeftChild()
		if leafL == nil || !leafL.isLeafNode() {
			t.Error()
		}
		leafR = tree.root.getRightChild()
		if leafR == nil || !leafR.isLeafNode() {
			t.Error()
		}
	}
	prefixL := makePrefixFromLeaf(leafL, t)
	prefixR := makePrefixFromLeaf(leafR, t)
	var leaf0, leaf1 prefixNode
	if bytes.Equal(prefixL, prefixR) {
		t.Error()
	}
	if bytes.Equal(prefixL, prefix0) {
		if !bytes.Equal(prefixR, prefix1) {
			t.Error()
		}
		leaf0, leaf1 = leafL, leafR
	} else if bytes.Equal(prefixL, prefix1) {
		if !bytes.Equal(prefixR, prefix0) {
			t.Error()
		}
		leaf0, leaf1 = leafR, leafL
	} else {
		t.Error()
	}
	expectedHash := leafHash(leaf0.getPartialPrefix(), []KeyHash{KeyHash{valueHash0, pos0}})
	if !bytes.Equal(leaf0.getHash(), expectedHash) {
		t.Error()
	}

	expectedHash = leafHash(leaf1.getPartialPrefix(), []KeyHash{KeyHash{valueHash1, pos1}})
	if !bytes.Equal(leaf1.getHash(), expectedHash) {
		t.Error()
	}
}

func TestPrefixAppendTwoValuesToOneKey(t *testing.T) {
	tree := NewPrefixTree()
	prefix := makePrefixFromKey([]byte{0b01})
	valueHash0 := crypto.Hash([]byte{0b101})
	valueHash1 := crypto.Hash([]byte{0b110})
	pos0 := uint32(31)
	pos1 := uint32(25)

	tree.PrefixAppend(prefix, valueHash0, pos0)
	tree.PrefixAppend(prefix, valueHash1, pos1)

	leaf := getOnlyChild(tree.root, t)
	if !leaf.isLeafNode() {
		t.Error()
	}

	if !bytes.Equal(prefix, makePrefixFromLeaf(leaf, t)) {
		t.Error()
	}

	valuesInLeaf := leaf.getValues()
	expectedValues := []KeyHash{KeyHash{valueHash0, pos0},
		KeyHash{valueHash1, pos1}}
	if !bytes.Equal(valuesInLeaf[0].Hash, expectedValues[0].Hash) ||
		valuesInLeaf[0].Pos != expectedValues[0].Pos {
		t.Error()
	}
	if !bytes.Equal(valuesInLeaf[1].Hash, expectedValues[1].Hash) ||
		valuesInLeaf[1].Pos != expectedValues[1].Pos {
		t.Error()
	}
	if !bytes.Equal(leafHash(prefix, expectedValues), leaf.getHash()) {
		t.Error()
	}

}

func TestAppendMultiple(t *testing.T) {
	tree, prefixes, valuesPerPrefix := prepareTestingTree(20, 3)
	for i := range prefixes {
		leaf := tree.getLeaf(prefixes[i])
		if !bytes.Equal(prefixes[i], makePrefixFromLeaf(leaf, t)) {
			t.Error()
		}
		if !bytes.Equal(leafHash(leaf.getPartialPrefix(), valuesPerPrefix[i]), leaf.getHash()) {
			t.Error()
		}
	}

}

func TestPrefixMembershipProof(t *testing.T) {
	tree, prefixes, _ := prepareTestingTree(20, 3)
	for _, p := range prefixes {
		membershipProof, leafValues := tree.generateMembershipProof(p)
		if membershipProof == nil {
			t.Error()
		} else if !bytes.Equal(computeRootHashMembership(p, membershipProof, leafValues), tree.root.hash) {
			t.Error()
		}
	}
	for i := 0; i < 3; i++ {
		nonMemberPrefix := getRandomPrefixNotInList(prefixes)
		membershipProof, _ := tree.generateMembershipProof(nonMemberPrefix)

		if membershipProof != nil {
			t.Error()
		}
	}
}

func TestPrefixNonMembershipProof(t *testing.T) {
	tree, prefixes, _ := prepareTestingTree(20, 3)

	for _, p := range prefixes {
		nonMembershipProof := tree.generateNonMembershipProof(p)
		if nonMembershipProof != nil {
			t.Error()
		}
	}
	for i := 0; i < 10; i++ {
		nonMemberPrefix := getRandomPrefixNotInList(prefixes)
		nonMembershipProof := tree.generateNonMembershipProof(nonMemberPrefix)

		if nonMembershipProof == nil {
			t.Error()
		} else if !bytes.Equal(computeRootHashNonMembership(nonMemberPrefix, nonMembershipProof), tree.root.hash) {
			t.Error()
		}
	}
}

func getOnlyChild(node prefixNode, t *testing.T) prefixNode {
	if node.isLeafNode() {
		t.Error()
	}
	right := node.getRightChild()
	left := node.getLeftChild()
	if right == nil && left == nil {
		t.Error()
	} else if right != nil && left != nil {
		t.Error()
	} else if right != nil && left == nil {
		return right
	} else if right == nil && left != nil {
		return left
	}
	t.Error()
	return nil
}

func makePrefixFromLeaf(node prefixNode, t *testing.T) (totalPrefix []byte) {
	if !node.isLeafNode() {
		t.Error()
	}
	for node.getParent() != nil {
		b := make([]byte, len(node.getPartialPrefix()))
		copy(b, node.getPartialPrefix())
		totalPrefix = append(b, totalPrefix...)
		node = node.getParent()
	}
	return
}

func generateRandomByteArray(size uint32) []byte {

	res := make([]byte, size)

	_, err := rand.Read(res)
	if err != nil {
		// handle error here
	}

	return res
}

func getRandomPrefix() []byte {
	return makePrefixFromKey(generateRandomByteArray(PREFIXVRFSIZE))
}

func getRandomPrefixNotInList(existingPrefixes [][]byte) (randPrefix []byte) {
	foundNonmemberPrefix := false
	for foundNonmemberPrefix == false {
		randPrefix = getRandomPrefix()
		matched := false
		for _, presentPrefix := range existingPrefixes {
			if bytes.Equal(randPrefix, presentPrefix) {
				foundNonmemberPrefix = true
			}
		}
		if !matched {
			foundNonmemberPrefix = true
		}
	}
	return
}

func prepareTestingTree(numKeys uint32, numValsPerKey uint32) (t *prefixTree, prefixes [][]byte, valsPerPrefix [][]KeyHash) {
	t = NewPrefixTree()
	var val, key uint32

	for key = 0; key < numKeys; key++ {
		prefixes = append(prefixes, getRandomPrefix())
		valsPerPrefix = append(valsPerPrefix, []KeyHash{})
	}

	var pos uint32 = 0
	for val = 0; val < numValsPerKey; val++ {
		for i, p := range prefixes {
			newValueHash := generateRandomByteArray(VALUEHASHSIZE)
			t.PrefixAppend(p, newValueHash, pos)

			valsPerPrefix[i] = append(valsPerPrefix[i], KeyHash{newValueHash, pos})
			pos++
		}
	}
	return t, prefixes, valsPerPrefix
}
