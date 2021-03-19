package core

import (
	"os"
	"reflect"
	"testing"
)

func TestLeafNodeSerialization(t *testing.T) {

	leafNode := &LeafNode{
		node: node{
			hash:      []byte("1"),
			isRight:   false,
			completed: true,
			index: index{
				depth: 0,
				shift: 3,
			},
		},
		contentHash: []byte("2"),
		key:         []byte("3"),
	}

	buf, err := leafNode.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializeLeafNode(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, leafNode) {
		t.Error()
	}
}

func TestInternalNodeSerialization(t *testing.T) {

	leafNode0 := &LeafNode{
		node: node{
			hash:      []byte("1"),
			isRight:   false,
			completed: true,
			index: index{
				depth: 0,
				shift: 0,
			},
		},
		contentHash: []byte("2"),
		key:         []byte("3"),
	}

	leafNode1 := &LeafNode{
		node: node{
			hash:      []byte("1"),
			isRight:   false,
			completed: true,
			index: index{
				depth: 0,
				shift: 1,
			},
		},
		contentHash: []byte("2"),
		key:         []byte("3"),
	}

	internalNode := &InternalNode{
		node: node{
			hash:      []byte("1"),
			isRight:   false,
			completed: true,
			index: index{
				depth: 1,
				shift: 0,
			},
		},
		leftChild:  leafNode0,
		rightChild: leafNode1,
		prefixTree: NewPrefixTree(),
	}

	leafNode0.setParent(internalNode)
	leafNode1.setParent(internalNode)

	buf, err := internalNode.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializeInternalNode(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, internalNode) {
		t.Error()
	}
}

func TestMerkleTreeSerialization(t *testing.T) {

	m := createTestingTree(8, 3)
	internalNode := m.root

	buf, err := internalNode.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializeInternalNode(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, internalNode) {
		t.Error()
	}
}

func TestPrefixLeafNodeSerialization(t *testing.T) {

	leafNode := &leafNode{
		hash: []byte("1"),
		values: []KeyHash{KeyHash{
			Hash: []byte("2"),
			Pos:  3,
		}},
		partialPrefix: []byte("4"),
	}

	buf, err := leafNode.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializePrefixLeafNode(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, leafNode) {
		t.Error()
	}
}

func TestPrefixInternalNodeSerialization(t *testing.T) {

	leafNode0 := &leafNode{
		hash: []byte("1"),
		values: []KeyHash{KeyHash{
			Hash: []byte("2"),
			Pos:  3,
		}},
		partialPrefix: []byte("4"),
	}

	leafNode1 := &leafNode{
		hash: []byte("5"),
		values: []KeyHash{KeyHash{
			Hash: []byte("6"),
			Pos:  7,
		}},
		partialPrefix: []byte("8"),
	}

	internalNode := &internalNode{
		hash:          []byte("9"),
		leftChild:     leafNode0,
		rightChild:    leafNode1,
		partialPrefix: []byte("10"),
	}

	leafNode0.setParent(internalNode)
	leafNode1.setParent(internalNode)

	buf, err := internalNode.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializePrefixInternalNode(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, internalNode) {
		t.Error()
	}
}

func TestPrefixTreeSerialization(t *testing.T) {

	prefix := NewPrefixTree()

	prefix.PrefixAppend(ConvertBitsToBytes([]byte("kian")), []byte("hash1"), 0)
	prefix.PrefixAppend(ConvertBitsToBytes([]byte("yuncong")), []byte("hash2"), 1)
	prefix.PrefixAppend(ConvertBitsToBytes([]byte("raluca")), []byte("hash3"), 2)

	buf, err := prefix.serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := deserializePrefixTree(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, prefix) {
		t.Error()
	}
}

func TestMerkleSquareSerialization(t *testing.T) {

	ms := createTestingTreeRepeatedKeys(50, 6, 5)

	buf, err := ms.Serialize()
	if err != nil {
		t.Error(err)
	}

	result, err := DeserializeMerkleSquare(buf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, ms) {
		t.Error()
	}
}

func TestFileReadWrite(t *testing.T) {

	ms := createTestingTreeRepeatedKeys(50, 6, 5)

	buf, err := ms.Serialize()
	if err != nil {
		t.Error(err)
	}

	_, err = WriteBytesToFile(buf, "./mytreeForTest")
	if err != nil {
		t.Error(err)
	}

	readBuf, err := ReadBytesFromFile("./mytreeForTest")
	if err != nil {
		t.Error()
	}

	result, err := DeserializeMerkleSquare(readBuf)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, ms) {
		t.Error()
	}

	err = os.Remove("./mytreeForTest")
	if err != nil {
		t.Error(err)
	}

}
