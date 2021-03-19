package core

import (
	"encoding/binary"

	crypto "github.com/ucbrise/MerkleSquare/lib/crypto"
)

// Internal node in Prefix Tree
type internalNode struct {
	parent        prefixNode
	hash          []byte
	leftChild     prefixNode
	rightChild    prefixNode
	partialPrefix []byte
}

// Leaf node representation in Prefix Tree
type leafNode struct {
	parent        prefixNode
	hash          []byte
	values        []KeyHash
	partialPrefix []byte
}

func newInteriorNode(parent prefixNode, partialPrefix []byte) *internalNode {

	res := &internalNode{
		hash:          nil,
		leftChild:     nil,
		rightChild:    nil,
		partialPrefix: partialPrefix,
	}
	parent.addChild(res)
	return res
}

func newLeafNode(parent prefixNode, valueHash []byte, pos uint32, partialPrefix []byte) *leafNode {
	if partialPrefix == nil || len(partialPrefix) <= 0 {
		panic("cannot create a leaf branch without a partial prefix")
	}

	list := []KeyHash{KeyHash{valueHash, pos}}

	res := &leafNode{
		hash:          nil,
		values:        list,
		partialPrefix: partialPrefix,
	}
	parent.addChild(res)
	return res
}

// helper function for internalNode and leafNode funcs
func getSibling(node prefixNode) prefixNode {
	if node.getParent() == nil {
		return nil
	}
	if node.isLeftChild() {
		return node.getParent().getRightChild()
	}
	return node.getParent().getLeftChild()
}

type prefixNode interface {
	isLeafNode() bool
	isLeftChild() bool
	getHash() []byte
	setParent(parent prefixNode)
	getParent() prefixNode
	getRightChild() prefixNode
	getLeftChild() prefixNode
	getPartialPrefix() []byte
	setPartialPrefix(newPrefix []byte)
	getValues() []KeyHash
	addValue(valueHash []byte, pos uint32)
	getSibling() prefixNode
	addChild(child prefixNode)
	getChild(prefix []byte, nextPrefixByteIndex uint32) prefixNode
	updateHash()
	serialize() ([]byte, error)
	getSize() int
	getNumNodes() int
}

func (node *internalNode) isLeafNode() bool                  { return false }
func (node *internalNode) isLeftChild() bool                 { return node.partialPrefix[0] == 0 }
func (node *internalNode) getHash() []byte                   { return node.hash }
func (node *internalNode) setParent(parent prefixNode)       { node.parent = parent }
func (node *internalNode) getParent() prefixNode             { return node.parent }
func (node *internalNode) getRightChild() prefixNode         { return node.rightChild }
func (node *internalNode) getLeftChild() prefixNode          { return node.leftChild }
func (node *internalNode) getPartialPrefix() []byte          { return node.partialPrefix }
func (node *internalNode) setPartialPrefix(newPrefix []byte) { node.partialPrefix = newPrefix }
func (node *internalNode) getValues() []KeyHash              { return nil }
func (node *internalNode) addValue(valueHash []byte, pos uint32) {
	return
}
func (node *internalNode) getSibling() prefixNode { return getSibling(node) }
func (node *internalNode) addChild(child prefixNode) {
	child.setParent(node)
	if child.getPartialPrefix()[0] == 0 {
		node.leftChild = child
	} else {
		node.rightChild = child
	}
}
func (node *internalNode) getChild(prefix []byte, nextPrefixByteIndex uint32) prefixNode {
	nextPrefixByte := prefix[nextPrefixByteIndex]
	if nextPrefixByte == 0 {
		return node.getLeftChild()
	}
	return node.getRightChild()

}

func (node *internalNode) updateHash() {
	var leftHash, rightHash []byte
	if node.leftChild != nil {
		leftHash = node.leftChild.getHash()
	}
	if node.rightChild != nil {
		rightHash = node.rightChild.getHash()
	}
	node.hash = crypto.Hash(node.partialPrefix, leftHash, rightHash)
}

func (node *internalNode) getSize() int {

	// pointer to parent, left and right child
	total := pointerSizeInBytes * 3

	// size of partialPrefix and hash
	total += binary.Size(node.getHash())
	if node.getPartialPrefix() != nil {
		// total += binary.Size(node.getPartialPrefix()) / 8
		total += binary.Size(node.getPartialPrefix())
	}
	// fmt.Println(total)

	// right tree, if exists
	if node.getRightChild() != nil {
		total += node.getRightChild().getSize()
	}

	// left tree, if exists
	if node.getLeftChild() != nil {
		total += node.getLeftChild().getSize()
	}

	return total
}

func (node *internalNode) getNumNodes() int {
	total := 1
	// right tree, if exists
	if node.getRightChild() != nil {
		total += node.getRightChild().getNumNodes()
	}

	// left tree, if exists
	if node.getLeftChild() != nil {
		total += node.getLeftChild().getNumNodes()
	}

	return total
}

func (node *leafNode) isLeafNode() bool                  { return true }
func (node *leafNode) isLeftChild() bool                 { return node.partialPrefix[0] == 0 }
func (node *leafNode) getHash() []byte                   { return node.hash }
func (node *leafNode) setParent(parent prefixNode)       { node.parent = parent }
func (node *leafNode) getParent() prefixNode             { return node.parent }
func (node *leafNode) getRightChild() prefixNode         { return nil }
func (node *leafNode) getLeftChild() prefixNode          { return nil }
func (node *leafNode) getPartialPrefix() []byte          { return node.partialPrefix }
func (node *leafNode) setPartialPrefix(newPrefix []byte) { node.partialPrefix = newPrefix }
func (node *leafNode) getValues() []KeyHash              { return node.values }
func (node *leafNode) addValue(valueHash []byte, pos uint32) {
	node.values = append(node.values, KeyHash{valueHash, pos})
}
func (node *leafNode) getSibling() prefixNode                                        { return getSibling(node) }
func (node *leafNode) addChild(child prefixNode)                                     {}
func (node *leafNode) getChild(prefix []byte, nextPrefixByteIndex uint32) prefixNode { return nil }
func (node *leafNode) updateHash()                                                   { node.hash = leafHash(node.partialPrefix, node.values) }

func (node *leafNode) getSize() int {

	// pointer to parent
	total := pointerSizeInBytes

	// size of partialPrefix and hash
	total += binary.Size(node.getPartialPrefix()) + binary.Size(node.getHash())

	// size of KeyHash values
	for _, value := range node.getValues() {
		total += binary.Size(value.Hash) + binary.Size(value.Pos)
	}

	return total
}

func (node *leafNode) getNumNodes() int {
	return 1
}

func leafHash(partialPrefix []byte, values []KeyHash) []byte {
	var flattenedValueHashes []byte
	for _, value := range values {
		flattenedValueHashes = append(flattenedValueHashes, value.Hash...)
		posAsBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(posAsBytes, value.Pos)
		flattenedValueHashes = append(flattenedValueHashes, posAsBytes...)
	}
	return crypto.Hash(partialPrefix, flattenedValueHashes)
}
