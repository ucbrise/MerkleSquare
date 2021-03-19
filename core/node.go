package core

import (
	"encoding/binary"
	"fmt"

	crypto "github.com/ucbrise/MerkleSquare/lib/crypto"
)

const pointerSizeInBytes = 8

// Base node struct
type node struct {
	hash      []byte
	parent    MerkleNode
	isRight   bool
	completed bool
	index     index
}

// InternalNode in Merkle Tree
type InternalNode struct {
	node
	leftChild  MerkleNode
	rightChild MerkleNode
	prefixTree *prefixTree
}

// LeafNode representation in MerkleTree
type LeafNode struct {
	node
	contentHash []byte
	key         []byte
}

type index struct {
	depth uint32
	shift uint32
}

// Called when a leaf node is created; fills in leaf node struct variables.
func (node *LeafNode) completeLeaf(key []byte, value []byte, signature []byte, pos uint32) {

	contentHash := ComputeContentHash(key, value, signature, pos)
	hashVal := crypto.Hash(makePrefixFromKey(key), contentHash)

	node.contentHash = contentHash
	node.hash = hashVal
	node.completed = true
	node.key = key
}

// Create ghost leaf node; call completeLeaf() to fill in other variables
func createLeafNode(parent MerkleNode, isRight bool, shift uint32) *LeafNode {
	return &LeafNode{
		node: node{
			parent:    parent,
			isRight:   isRight,
			completed: false,
			index: index{
				depth: 0,
				shift: shift,
			},
		},
	}
}

// Create ghost internal node; call internalNode.complete() to complete
func createInternalNode(parent MerkleNode, depth uint32, isRight bool, shift uint32) *InternalNode {
	return &InternalNode{
		node: node{
			parent:    parent,
			isRight:   isRight,
			completed: false,
			index: index{
				depth: depth,
				shift: shift,
			},
		},
		prefixTree: NewPrefixTree(),
	}
}

// Creates root node (called when initializing ghost nodes)
func createRootNode(depth uint32) MerkleNode {
	return &InternalNode{
		node: node{
			completed: false,
			index: index{
				depth: depth,
				shift: 0,
			},
		},
		prefixTree: NewPrefixTree(),
	}
}

// MerkleNode interface for leaf/internal nodes
type MerkleNode interface {
	isLeafNode() bool
	setParent(MerkleNode)
	getHash() []byte
	complete()
	isComplete() bool
	isRightChild() bool
	getParent() MerkleNode
	createRightChild() MerkleNode
	createLeftChild() MerkleNode
	getRightChild() MerkleNode
	getLeftChild() MerkleNode
	getDepth() uint32
	print()
	getPrefixTree() *prefixTree
	getShift() uint32
	getIndex() index
	getSibling() Sibling
	getContentHash() []byte
	getPrefix() []byte
	serialize() ([]byte, error)
	getSize() int
}

//**********************************
// INTERFACE METHODS
//**********************************

func (node *InternalNode) complete() {
	node.getPrefixTree().complete()
	hashVal := crypto.Hash(node.leftChild.getHash(), node.rightChild.getHash(), node.getPrefixTree().getHash())

	node.hash = hashVal
	node.completed = true
}

// Called by internal nodes; creates a right child (of type internal or leaf)
func (node *InternalNode) createRightChild() MerkleNode {

	var newNode MerkleNode
	if node.getDepth() == 1 {
		newNode = createLeafNode(node, true, node.getShift()*2+1)
	} else {
		newNode = createInternalNode(node, node.getDepth()-1, true, node.getShift()*2+1)
	}

	node.rightChild = newNode

	return newNode
}

func (node *InternalNode) createLeftChild() MerkleNode {
	var newNode MerkleNode
	if node.getDepth() == 1 {
		newNode = createLeafNode(node, false, node.getShift()*2)
	} else {
		newNode = createInternalNode(node, node.getDepth()-1, false, node.getShift()*2)
	}

	node.leftChild = newNode

	return newNode
}

func (node *InternalNode) getSibling() Sibling {

	var hash []byte
	if node.isRightChild() {
		hash = node.getParent().getLeftChild().getHash()
	} else {
		hash = node.getParent().getRightChild().getHash()
	}

	return Sibling{
		Hash: hash,
	}
}

func (node *LeafNode) getSibling() Sibling {

	var hash []byte
	if node.isRightChild() {
		hash = node.getParent().getLeftChild().getHash()
	} else {
		hash = node.getParent().getRightChild().getHash()
	}

	return Sibling{
		Hash: hash,
	}
}

func (node *LeafNode) getSize() int {

	// pointer to parent 8 bytes
	total := pointerSizeInBytes

	// hash, isRight, isComplete sizes
	total += binary.Size(node.hash) + binary.Size(node.isRight) + binary.Size(node.isComplete)

	// size of index
	total += binary.Size(node.index.depth) + binary.Size(node.index.shift)

	// content hash and key
	total += binary.Size(node.contentHash) + binary.Size(node.key)

	return total
}

func (node *InternalNode) getSize() int {
	// pointer to parent 8 bytes + left and right child pointers + prefix tree pointer
	total := pointerSizeInBytes * 4

	// hash, isRight, isComplete sizes
	total += binary.Size(node.hash) + binary.Size(node.isRight) + binary.Size(node.isComplete)

	// size of index
	total += binary.Size(node.index.depth) + binary.Size(node.index.shift)

	// right child
	if node.getRightChild() != nil {
		total += node.getRightChild().getSize()
	}

	if node.getLeftChild() != nil {
		total += node.getLeftChild().getSize()
	}

	// prefix tree size
	total += node.getPrefixTree().getSize()

	return total
}

func (node *InternalNode) isComplete() bool            { return node.completed }
func (node *InternalNode) isRightChild() bool          { return node.isRight }
func (node *InternalNode) getParent() MerkleNode       { return node.parent }
func (node *InternalNode) isLeafNode() bool            { return false }
func (node *InternalNode) setParent(parent MerkleNode) { node.parent = parent }
func (node *InternalNode) getHash() []byte             { return node.hash }
func (node *InternalNode) getRightChild() MerkleNode   { return node.rightChild }
func (node *InternalNode) getLeftChild() MerkleNode    { return node.leftChild }
func (node *InternalNode) getDepth() uint32            { return node.index.depth }
func (node *InternalNode) print()                      { fmt.Print(node.isComplete()) }
func (node *InternalNode) getPrefixTree() *prefixTree  { return node.prefixTree }
func (node *InternalNode) getShift() uint32            { return node.index.shift }
func (node *InternalNode) getIndex() index             { return node.index }
func (node *InternalNode) getContentHash() []byte      { return []byte("") }
func (node *InternalNode) getPrefix() []byte           { return []byte("") }

func (node *LeafNode) isComplete() bool             { return node.completed }
func (node *LeafNode) isRightChild() bool           { return node.isRight }
func (node *LeafNode) getParent() MerkleNode        { return node.parent }
func (node *LeafNode) isLeafNode() bool             { return true }
func (node *LeafNode) setParent(parent MerkleNode)  { node.parent = parent }
func (node *LeafNode) getHash() []byte              { return node.hash }
func (node *LeafNode) complete()                    {}
func (node *LeafNode) createLeftChild() MerkleNode  { return &LeafNode{} }
func (node *LeafNode) createRightChild() MerkleNode { return &LeafNode{} }
func (node *LeafNode) getRightChild() MerkleNode    { return &LeafNode{} }
func (node *LeafNode) getLeftChild() MerkleNode     { return &LeafNode{} }
func (node *LeafNode) getDepth() uint32             { return 0 }
func (node *LeafNode) print()                       { fmt.Print(node.isComplete()) }
func (node *LeafNode) getPrefixTree() *prefixTree   { return NewPrefixTree() }
func (node *LeafNode) getShift() uint32             { return node.index.shift }
func (node *LeafNode) getIndex() index              { return node.index }
func (node *LeafNode) getContentHash() []byte       { return node.contentHash }
func (node *LeafNode) getPrefix() []byte            { return makePrefixFromKey(node.key) }
