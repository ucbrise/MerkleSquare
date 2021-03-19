package core

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

//*******************************
// CORE METHOD TESTS
//*******************************

func TestAppend(t *testing.T) {

	m := NewMerkleSquare(4)
	m.Append([]byte("key1"), []byte("value1"), []byte("signature1"))
	m.Append([]byte("key2"), []byte("value2"), []byte("signature2"))

	l1 := m.getLeafNode(0)
	l2 := m.getLeafNode(1)

	if !l1.isComplete() || !l2.isComplete() || !l1.getParent().isComplete() {
		t.Error()
	}

	m.Append([]byte("key3"), []byte("value3"), []byte("signature3"))
	l3 := m.getLeafNode(2)
	l4 := m.getLeafNode(3)

	if !l3.isComplete() || l4.isComplete() || l3.getParent().isComplete() {
		t.Error()
	}

	if m.Size != 3 {
		t.Error()
	}

	m1 := NewMerkleSquare(20)
	numAppends := 1000
	for i := 0; i < numAppends; i++ {
		m1.Append([]byte("k"), []byte("v"), []byte("s"))
	}

	if m1.Size != 1000 {
		t.Error()
	}
}

func TestGenerateExistenceProof(t *testing.T) {

	m0 := createTestingTree(7, 3)
	digest0 := m0.GetDigest()

	m1 := createTestingTree(8, 3)
	digest1 := m1.GetDigest()

	m2 := createTestingTreeRepeatedKeys(15, 4, 2)
	digest2 := m2.GetDigest()

	m3 := createTestingTreeRepeatedKeys(1000, 20, 250)
	digest3 := m3.GetDigest()

	tables := []struct {
		key       []byte
		value     []byte
		signature []byte
		pos       uint32
		height    uint32
		oldSize   uint32
		node      MerkleNode
		rootHash  []byte
		ms        *MerkleSquare
		digest    *Digest
	}{
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 0, 7, m0.getNode(0, 0), digest0.Roots[0], m0, digest0},
		{[]byte("key1"), []byte("value1"), []byte("signature1"), 1, 0, 7, m0.getNode(0, 1), digest0.Roots[0], m0, digest0},
		{[]byte("key2"), []byte("value2"), []byte("signature2"), 2, 0, 7, m0.getNode(0, 2), digest0.Roots[0], m0, digest0},
		{[]byte("key3"), []byte("value3"), []byte("signature3"), 3, 0, 7, m0.getNode(0, 3), digest0.Roots[0], m0, digest0},
		{[]byte("key4"), []byte("value4"), []byte("signature4"), 4, 0, 7, m0.getNode(0, 4), digest0.Roots[1], m0, digest0},
		{[]byte("key5"), []byte("value5"), []byte("signature5"), 5, 0, 7, m0.getNode(0, 5), digest0.Roots[1], m0, digest0},
		{[]byte("key6"), []byte("value6"), []byte("signature6"), 6, 0, 7, m0.getNode(0, 6), digest0.Roots[2], m0, digest0},
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 1, 7, m0.getNode(1, 0), digest0.Roots[0], m0, digest0},
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 2, 8, m1.getNode(2, 0), digest1.Roots[0], m1, digest1},
		{[]byte("key1"), []byte("value1"), []byte("signature1"), 1, 2, 8, m1.getNode(2, 0), digest1.Roots[0], m1, digest1},
		{[]byte("key2"), []byte("value2"), []byte("signature2"), 2, 0, 8, m1.getNode(0, 2), digest1.Roots[0], m1, digest1},
		{[]byte("key0"), []byte("value2"), []byte("signature0"), 2, 2, 15, m2.getNode(2, 0), digest2.Roots[0], m2, digest2},
		{[]byte("key0"), []byte("value6"), []byte("signature0"), 6, 0, 15, m2.getNode(0, 6), digest2.Roots[0], m2, digest2},
		{[]byte("key1"), []byte("value9"), []byte("signature1"), 9, 0, 15, m2.getNode(0, 9), digest2.Roots[1], m2, digest2},
		{[]byte("key1"), []byte("value251"), []byte("signature1"), 251, 0, 1000, m3.getNode(0, 251), digest3.Roots[0], m3, digest3},
	}

	for _, table := range tables {
		proof := table.ms.GenerateExistenceProof(table.key, table.pos, table.height, table.oldSize)

		oldHashes := table.ms.generateKeyHash(table.key)
		var nodehash []byte
		if table.height == 0 {
			nodehash = ComputeLeafNodeHash(table.key, table.value, table.signature, table.pos)
		} else {
			nodehash = table.node.getHash()
		}

		res, _, _ := VerifyExistenceProof(table.digest, nodehash, table.key, table.pos, table.height, proof, oldHashes)

		if !res {
			t.Error()
		}
	}
}

func TestGenerateExtensionProof(t *testing.T) {

	m0 := createTestingTree(7, 3)
	m1 := createTestingTree(15, 4)
	m2 := createTestingTree(3500, 16)

	tables := []struct {
		ms            *MerkleSquare
		oldSize       uint32
		requestedSize uint32
	}{
		{m0, 1, 7},
		{m1, 1, 8},
		{m1, 7, 15},
		{m1, 1, 15},
		{m2, 1000, 2000},
		{m2, 150, 2100},
		{m2, 350, 2200},
		{m2, 1000, 3500},
	}

	for _, table := range tables {
		oldDigest := table.ms.GetOldDigest(table.oldSize)
		newDigest := table.ms.GetOldDigest(table.requestedSize)

		proof := table.ms.GenerateExtensionProof(table.oldSize, table.requestedSize)

		if !VerifyExtensionProof(oldDigest, newDigest, proof) {
			t.Error()
		}
	}
}

func TestProveFirst(t *testing.T) {
	m0 := createTestingTree(7, 3)
	digest0 := m0.GetDigest()

	m1 := createTestingTreeRepeatedKeys(15, 4, 1)
	digest1 := m1.GetDigest()

	m2 := createTestingTreeRepeatedKeys(1000, 20, 700)
	digest2 := m2.GetDigest()

	tables := []struct {
		key       []byte
		value     []byte
		signature []byte
		pos       uint32
		oldSize   uint32
		digest    *Digest
		ms        *MerkleSquare
	}{
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 7, digest0, m0},
		{[]byte("key1"), []byte("value1"), []byte("signature1"), 1, 7, digest0, m0},
		{[]byte("key2"), []byte("value2"), []byte("signature2"), 2, 7, digest0, m0},
		{[]byte("key3"), []byte("value3"), []byte("signature3"), 3, 7, digest0, m0},
		{[]byte("key4"), []byte("value4"), []byte("signature4"), 4, 7, digest0, m0},
		{[]byte("key5"), []byte("value5"), []byte("signature5"), 5, 7, digest0, m0},
		{[]byte("key6"), []byte("value6"), []byte("signature6"), 6, 7, digest0, m0},
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 15, digest1, m1},
		{[]byte("key1"), []byte("value1"), []byte("signature1"), 1, 1000, digest2, m2},
		{[]byte("key650"), []byte("value650"), []byte("signature650"), 650, 1000, digest2, m2},
	}

	for _, table := range tables {
		proof := table.ms.ProveFirst(table.key, table.value, table.pos, table.oldSize)
		if !VerifyMKProof(table.digest, table.key, table.value, table.signature, table.pos, proof) {
			t.Error()
		}
	}
}

func TestProveLatest(t *testing.T) {
	m0 := createTestingTree(7, 3)
	digest0 := m0.GetDigest()

	m1 := createTestingTreeRepeatedKeys(15, 4, 12)
	digest1 := m1.GetDigest()

	m2 := createTestingTreeRepeatedKeys(1000, 20, 700)
	digest2 := m2.GetDigest()

	tables := []struct {
		key       []byte
		value     []byte
		signature []byte
		pos       uint32
		oldSize   uint32
		digest    *Digest
		ms        *MerkleSquare
	}{
		{[]byte("key0"), []byte("value0"), []byte("signature0"), 0, 7, digest0, m0},
		{[]byte("key1"), []byte("value1"), []byte("signature1"), 1, 7, digest0, m0},
		{[]byte("key2"), []byte("value2"), []byte("signature2"), 2, 7, digest0, m0},
		{[]byte("key3"), []byte("value3"), []byte("signature3"), 3, 7, digest0, m0},
		{[]byte("key4"), []byte("value4"), []byte("signature4"), 4, 7, digest0, m0},
		{[]byte("key5"), []byte("value5"), []byte("signature5"), 5, 7, digest0, m0},
		{[]byte("key6"), []byte("value6"), []byte("signature6"), 6, 7, digest0, m0},
		{[]byte("key0"), []byte("value12"), []byte("signature0"), 12, 15, digest1, m1},
		{[]byte("key1"), []byte("value13"), []byte("signature1"), 13, 15, digest1, m1},
		{[]byte("key2"), []byte("value14"), []byte("signature2"), 14, 15, digest1, m1},
		{[]byte("key3"), []byte("value3"), []byte("signature3"), 3, 15, digest1, m1},
		{[]byte("key1"), []byte("value701"), []byte("signature1"), 701, 1000, digest2, m2},
	}

	for _, table := range tables {
		proof := table.ms.ProveLatest(table.key, table.value, table.pos, table.oldSize)
		if !VerifyPKProof(table.digest, table.key, table.value, table.signature, table.pos, proof) {
			t.Error()
		}
	}

}

func TestProveNonexistence(t *testing.T) {
	m0 := createTestingTree(15, 5)

	tables := []struct {
		key      []byte
		mskPos   uint32
		currSize uint32
		ms       *MerkleSquare
	}{
		{[]byte("key0"), 0, 4, m0},
		{[]byte("key1"), 1, 9, m0},
		{[]byte("key2"), 2, 8, m0},
		{[]byte("key3"), 3, 15, m0},
		{[]byte("key4"), 4, 13, m0},
		{[]byte("key5"), 5, 10, m0},
		{[]byte("key6"), 6, 14, m0},
	}

	for _, table := range tables {
		proof := m0.ProveNonexistence(table.key, table.mskPos, table.currSize)
		newDigest := m0.GetOldDigest(table.currSize)

		if !VerifyNonexistenceProof(table.key, table.mskPos, newDigest, proof) {
			t.Error()
		}
	}
}

func TestBatchedLookup(t *testing.T) {

	m0 := createTestingTreeRepeatedKeys(30, 5, 4)

	tables := []struct {
		key          []byte
		endSize      uint32
		keyPositions []uint32
		exclude      []uint32
		ms           *MerkleSquare
	}{
		{[]byte("key1"), 30, []uint32{1, 5, 13, 17, 21, 25, 29}, []uint32{9}, m0},
		{[]byte("key2"), 30, []uint32{2, 6, 14, 18, 22, 26}, []uint32{10}, m0},
		{[]byte("key1"), 30, []uint32{5, 9, 21, 25, 29}, []uint32{1, 13, 17}, m0},
		{[]byte("key0"), 29, []uint32{0, 4, 16, 20, 24, 28}, []uint32{8, 12}, m0},
		{[]byte("key1"), 29, []uint32{1, 5, 17, 21}, []uint32{9, 13, 25, 29}, m0},
		{[]byte("key3"), 30, []uint32{3, 7}, []uint32{11, 15, 19, 23, 27}, m0},
		{[]byte("key3"), 15, []uint32{3, 7, 11}, []uint32{15, 19, 23, 27}, m0},
		{[]byte("key2"), 15, []uint32{2, 6, 10, 14}, []uint32{18, 22, 26}, m0},
	}

	for _, table := range tables {
		proof, err := table.ms.GenerateBatchedLookupProof(0, table.endSize, table.key, table.keyPositions)

		if err != nil {
			t.Error(err)
		}
		keyHashes := table.ms.generateKeyHash(table.key, table.exclude...)

		digest := table.ms.GetOldDigest(table.endSize)

		verified, err := VerifyBatchedLookupProof(0, table.key, keyHashes, digest, proof)
		if !verified {
			t.Error(err)
		}
	}
}

//*******************************
// HELPER METHOD TESTS
//*******************************

func TestAddKeyHash(t *testing.T) {

	otherHashes := []KeyHash{
		KeyHash{Pos: 1},
		KeyHash{Pos: 3},
		KeyHash{Pos: 5},
	}

	tables := []struct {
		key       []byte
		value     []byte
		signature []byte
		pos       uint32
		expected  uint32
	}{
		{[]byte("key"), []byte("val"), []byte("sig"), 0, 0},
		{[]byte("key"), []byte("val"), []byte("sig"), 2, 1},
		{[]byte("key"), []byte("val"), []byte("sig"), 4, 2},
		{[]byte("key"), []byte("val"), []byte("sig"), 6, 3},
	}

	for _, table := range tables {
		res := AddKeyHash(otherHashes, table.key, table.value, table.signature, table.pos)

		if res[table.expected].Pos != table.pos {
			t.Error()
		}
	}
}

func TestComputeMemberKeys(t *testing.T) {

	m0 := createTestingTreeRepeatedKeys(30, 6, 3)

	tables := []struct {
		ms      *MerkleSquare
		oldSize uint32
		key     []byte
		left    uint32
		rigth   uint32
		result  []uint32
	}{
		{m0, 30, []byte("key0"), 10, 16, []uint32{12, 15}},
		{m0, 30, []byte("key0"), 0, 30, []uint32{0, 3, 6, 9, 12, 15, 18, 21, 24, 27}},
		{m0, 30, []byte("key1"), 29, 30, []uint32{}},
		{m0, 30, []byte("key1"), 27, 30, []uint32{28}},
		{m0, 30, []byte("key1"), 5, 6, []uint32{}},
		{m0, 30, []byte("key1"), 5, 19, []uint32{7, 10, 13, 16, 19}},
		{m0, 30, []byte("key1"), 0, 30, []uint32{1, 4, 7, 10, 13, 16, 19, 22, 25, 28}},
	}

	for _, table := range tables {
		res := computeMemberKeys(table.oldSize, table.ms.generateKeyHash(table.key), table.left, table.rigth)

		if len(res) != len(table.result) {
			t.Error("Wrong return size")
		}

		for i, keyHash := range res {
			if keyHash.Pos != table.result[i] {
				t.Errorf("Expected %d but got %d", table.result[i], keyHash.Pos)
			}
		}
	}
}

func TestFilterOutKeyHash(t *testing.T) {

	otherHashes := []KeyHash{
		KeyHash{Pos: 1},
		KeyHash{Pos: 3},
		KeyHash{Pos: 5},
		KeyHash{Pos: 7},
		KeyHash{Pos: 9},
	}

	tables := []struct {
		pos      []uint32
		expected []uint32
	}{
		{[]uint32{1}, []uint32{3, 5, 7, 9}},
		{[]uint32{9}, []uint32{1, 3, 5, 7}},
		{[]uint32{1, 5, 9}, []uint32{3, 7}},
		{[]uint32{1, 3, 5, 7, 9}, []uint32{}},
		{[]uint32{5, 9}, []uint32{1, 3, 7}},
		{[]uint32{}, []uint32{1, 3, 5, 7, 9}},
	}

	for _, table := range tables {

		res := filterOutKeyHash(otherHashes, table.pos...)

		for i, elem := range res {
			if table.expected[i] != elem.Pos {
				t.Error()
			}
		}
	}
}

func TestCombineKeyHashes(t *testing.T) {

	tables := []struct {
		otherHashes0 []KeyHash
		otherHashes1 []KeyHash
		expected     []uint32
	}{
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 3},
			KeyHash{Pos: 5},
			KeyHash{Pos: 7},
			KeyHash{Pos: 9},
		}, []KeyHash{
			KeyHash{Pos: 2},
			KeyHash{Pos: 6},
			KeyHash{Pos: 10},
			KeyHash{Pos: 11},
			KeyHash{Pos: 12},
		}, []uint32{1, 2, 3, 5, 6, 7, 9, 10, 11, 12}},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 3},
		}, []KeyHash{},
			[]uint32{1, 3}},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 3},
		}, []KeyHash{
			KeyHash{Pos: 4},
			KeyHash{Pos: 5},
		},
			[]uint32{1, 3, 4, 5}},
	}

	for _, table := range tables {

		res := combineKeyHashes(table.otherHashes0, table.otherHashes1)

		for i, elem := range res {
			if table.expected[i] != elem.Pos {
				t.Error()
			}
		}
	}
}

func TestCheckKeyHashes(t *testing.T) {

	tables := []struct {
		lookupHashes []KeyHash
		otherHashes  []KeyHash
		expected     bool
	}{
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 10},
			KeyHash{Pos: 25},
			KeyHash{Pos: 35},
		}, []KeyHash{
			KeyHash{Pos: 2},
		},
			false},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 10},
			KeyHash{Pos: 25},
			KeyHash{Pos: 35},
		}, []KeyHash{
			KeyHash{Pos: 12},
		},
			true},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 10},
			KeyHash{Pos: 25},
			KeyHash{Pos: 35},
		}, []KeyHash{
			KeyHash{Pos: 12},
			KeyHash{Pos: 13},
			KeyHash{Pos: 24},
			KeyHash{Pos: 38},
		},
			true},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 10},
			KeyHash{Pos: 25},
			KeyHash{Pos: 35},
		}, []KeyHash{
			KeyHash{Pos: 12},
			KeyHash{Pos: 13},
			KeyHash{Pos: 24},
			KeyHash{Pos: 34},
		},

			false},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 10},
			KeyHash{Pos: 25},
			KeyHash{Pos: 35},
		}, []KeyHash{},
			true},
		{[]KeyHash{
			KeyHash{Pos: 1},
			KeyHash{Pos: 2},
			KeyHash{Pos: 10},
		}, []KeyHash{
			KeyHash{Pos: 5},
			KeyHash{Pos: 15},
		},
			true},
	}

	for _, table := range tables {

		if checkKeyHashes(table.lookupHashes, table.otherHashes) != table.expected {
			t.Error()
		}
	}
}

func TestGetRootRange(t *testing.T) {

	tables := []struct {
		rootIndex   uint32
		size        uint32
		leftResult  uint32
		rightResult uint32
	}{
		{0, 2906, 0, 2047},
		{1, 2906, 2048, 2559},
		{2, 2906, 2560, 2815},
		{3, 2906, 2816, 2879},
		{4, 2906, 2880, 2895},
		{5, 2906, 2896, 2903},
		{6, 2906, 2904, 2905},
	}

	for _, table := range tables {
		left, right := getRootRange(table.rootIndex, table.size)

		if left != table.leftResult || right != table.rightResult {
			t.Errorf("Expected: %d, %d. Got left: %d right: %d", table.leftResult, table.rightResult, left, right)
		}
	}
}

func TestCalculateLeftRightRange(t *testing.T) {

	tables := []struct {
		shift       uint32
		height      uint32
		leftResult  uint32
		rightResult uint32
	}{
		{0, 4, 0, 15},
		{2, 3, 16, 23},
	}

	for _, table := range tables {
		left, right := calculateLeftRightRange(table.shift, table.height)

		if left != table.leftResult || right != table.rightResult {
			t.Errorf("Expected: %d, %d. Got left: %d right: %d", table.leftResult, table.rightResult, left, right)
		}
	}

}

func TestCalculateParentShift(t *testing.T) {

	tables := []struct {
		pos          uint32
		parentHeight uint32
		result       uint32
	}{
		{0, 4, 0},
		{1, 4, 0},
		{15, 4, 0},
		{16, 4, 1},
		{16, 3, 2},
		{24, 3, 3},
		{24, 2, 6},
		{30, 0, 30},
	}

	for _, table := range tables {
		result := calculateParentShift(table.pos, table.parentHeight)
		if result != table.result {
			t.Error()
		}
	}

}

func TestIsRightOf(t *testing.T) {

}

func TestGetOldDepth(t *testing.T) {

	tables := []struct {
		pos    uint32
		Size   uint32
		result uint32
	}{
		{0, 22, 4},
		{1, 22, 4},
		{5, 22, 4},
		{15, 22, 4},
		{16, 22, 2},
		{20, 22, 1},
		{21, 22, 1},
		{30, 31, 0},
	}

	for _, table := range tables {
		result := GetOldDepth(table.pos, table.Size)
		if result != table.result {
			t.Error()
		}
	}
}

func TestGetOldRoots(t *testing.T) {

	m := createTestingTree(7, 3)

	digest := m.GetDigest()

	m.Append([]byte("key8"), []byte("value8"), []byte("signature8"))

	newDigest := m.GetDigest()

	if len(newDigest.Roots) != 1 {
		t.Error()
	}

	oldRoots := m.getOldRoots(7)

	for i, root := range oldRoots {

		if !bytes.Equal(root.getHash(), digest.Roots[i]) {
			t.Error()
		}
	}
}

func TestGetRootIndex(t *testing.T) {

	tables := []struct {
		pos    uint32
		Size   uint32
		result uint32
	}{
		{5, 22, 0},
		{16, 22, 1},
		{21, 22, 2},
	}

	for _, table := range tables {
		result := getRootIndex(table.pos, table.Size)
		if uint32(result) != table.result {
			t.Error()
		}
	}
}

func TestGetAddNode(t *testing.T) {

	m := createPopulatedTree(2)

	tables := []struct {
		depth uint32
		shift uint32
	}{
		{0, 0},
		{0, 1},
		{0, 2},
		{0, 3},
		{1, 0},
		{1, 1},
		{2, 0},
	}

	for _, table := range tables {
		node := m.getNode(table.depth, table.shift)
		if node.getDepth() != table.depth || node.getShift() != table.shift {
			t.Error()
		}
	}
}

func TestPopAddRoot(t *testing.T) {

	m := NewMerkleSquare(4)
	newRoot := createRootNode(2)

	m.addRoot(newRoot)

	if len(m.Roots) != 1 {
		t.Error()
	}

	poppedRoot := m.pop()

	if len(m.Roots) != 0 || poppedRoot != newRoot {
		t.Error()
	}
}

func TestNewMerkleSquare(t *testing.T) {

	m := NewMerkleSquare(4)

	node := m.root

	for node.getDepth() != 0 {

		if node.getRightChild() != nil {
			t.Error()
		}

		if node.getPrefixTree() == nil {
			t.Error()
		}

		node = node.getLeftChild()
	}
}

//*******************************
// TESTING METHODS
//*******************************

func (m *MerkleSquare) generateKeyHash(key []byte, exclude ...uint32) []KeyHash {
	prefix := makePrefixFromKey(key)
	res := []KeyHash{}

	for i, j := uint32(0), 0; i < m.Size; i++ {

		if j < len(exclude) && exclude[j] == i {
			j++
			continue
		}

		node := m.getNode(0, i)

		if bytes.Equal(prefix, node.getPrefix()) {
			res = append(res, KeyHash{
				Hash: node.getContentHash(),
				Pos:  node.getShift(),
			})
		}
	}

	return res
}

func createPopulatedTree(depth uint32) *MerkleSquare {
	return createTestingTree(1<<depth, depth)
}

func createTestingTreeRepeatedKeys(size uint32, depth uint32, numKeys uint32) *MerkleSquare {
	m := NewMerkleSquare(depth)

	var i uint32
	for i = 0; i < size; i++ {
		k := i % numKeys
		m.Append([]byte(fmt.Sprintf("key%d", k)), []byte(fmt.Sprintf("value%d", i)), []byte(fmt.Sprintf("signature%d", k)))
	}

	return m
}

func createTestingTree(size uint32, depth uint32) *MerkleSquare {
	m := NewMerkleSquare(depth)

	var i uint32
	for i = 0; i < size; i++ {
		m.Append([]byte(fmt.Sprintf("key%d", i)), []byte(fmt.Sprintf("value%d", i)), []byte(fmt.Sprintf("signature%d", i)))
	}

	return m
}

func printMerkleTree(m *MerkleSquare) {

	node := m.root
	level := node.getDepth()

	for level > 0 {
		printLine(node, level)
		level = level - 1
	}

	printLine(node, 0)
}

func printLine(node MerkleNode, level uint32) {

	nodes := []MerkleNode{}

	getNodes(node, level, &nodes)

	i := 0
	for i < len(nodes) {
		nodes[i].print()
		i++
	}
	fmt.Println()
}

func getNodes(node MerkleNode, level uint32, nodes *[]MerkleNode) {
	if node.getDepth() == level {
		newSlice := append(*nodes, node)
		*nodes = newSlice
	} else {
		if !isNil(node.getLeftChild()) {
			getNodes(node.getLeftChild(), level, nodes)
		}

		if !isNil(node.getRightChild()) {
			getNodes(node.getRightChild(), level, nodes)
		}
	}
}

func isNil(node MerkleNode) bool {
	return node == nil || reflect.ValueOf(node).IsNil()
}
