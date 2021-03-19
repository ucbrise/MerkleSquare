package core

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// JSONMerkleSquare representation
type JSONMerkleSquare struct {
	Root  []byte `json:"root"`
	Size  int    `json:"size"`
	Depth int    `json:"depth"`
}

// JSONPrefixTree representation
type JSONPrefixTree struct {
	Root       []byte `json:"root"`
	IsComplete bool   `json:"isComplete"`
}

// JSONLeafNode representation
type JSONLeafNode struct {
	Hash        []byte `json:"hash"`
	IsRight     bool   `json:"isRight"`
	Completed   bool   `json:"completed"`
	Depth       int    `json:"depth"`
	Shift       int    `json:"shift"`
	ContentHash []byte `json:"contentHash"`
	Key         []byte `json:"key"`
}

// JSONInternalNode representation
type JSONInternalNode struct {
	Hash       []byte `json:"hash"`
	IsRight    bool   `json:"isRight"`
	Completed  bool   `json:"completed"`
	Depth      int    `json:"depth"`
	Shift      int    `json:"shift"`
	LeftChild  []byte `json:"leftChild"`
	RightChild []byte `json:"rightChild"`
	PrefixTree []byte `json:"prefixTree"`
	// parent, index, prefix tree
}

// JSONPrefixLeafNode representation
type JSONPrefixLeafNode struct {
	Hash          []byte `json:"hash"`
	Values        []byte `json:"values"`
	PartialPrefix []byte `json:"partialPrefix"`
}

// JSONPrefixInternalNode representation
type JSONPrefixInternalNode struct {
	Hash          []byte `json:"hash"`
	LeftChild     []byte `json:"leftChild"`
	RightChild    []byte `json:"rightChild"`
	PartialPrefix []byte `json:"partialPrefix"`
	LeftLeaf      bool   `json:"leftLeaf"`
	RightLeaf     bool   `json:"rightLeaf"`
}

//*******************************
// CORE METHODS
//*******************************

// WriteBytesToFile writes a []byte to a given file
func WriteBytesToFile(buf []byte, path string) (int, error) {

	file, err := os.Create(path)
	if err != nil {
		return 0, err
	}

	defer file.Close()

	n, err := file.Write(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// ReadBytesFromFile reads all bytes from a given file
func ReadBytesFromFile(path string) ([]byte, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	return ioutil.ReadAll(file)
}

// Serialize serializes a Merkle Square struct
func (ms *MerkleSquare) Serialize() ([]byte, error) {

	tree, err := ms.root.serialize()
	if err != nil {
		return nil, err
	}

	jsonMS := JSONMerkleSquare{
		tree,
		int(ms.Size),
		int(ms.depth),
	}

	b, err := json.Marshal(jsonMS)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DeserializeMerkleSquare deserializes a []byte that is a MerkleSquare
func DeserializeMerkleSquare(buf []byte) (*MerkleSquare, error) {

	var jsonMerkle JSONMerkleSquare
	err := json.Unmarshal(buf, &jsonMerkle)

	if err != nil {
		return nil, err
	}

	root, err := deserializeInternalNode(jsonMerkle.Root)
	if err != nil {
		return nil, err
	}

	res := &MerkleSquare{
		root:  root,
		Size:  uint32(jsonMerkle.Size),
		depth: uint32(jsonMerkle.Depth),
	}

	res.Roots = res.getOldRoots(res.Size)
	res.next = res.getNode(0, res.Size)

	return res, nil
}

func (prefixTree *prefixTree) serialize() ([]byte, error) {

	tree, err := prefixTree.root.serialize()
	if err != nil {
		return nil, err
	}

	jsonPrefix := JSONPrefixTree{
		tree,
		prefixTree.isComplete,
	}

	b, err := json.Marshal(jsonPrefix)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func deserializePrefixTree(buf []byte) (*prefixTree, error) {

	var jsonPrefix JSONPrefixTree
	err := json.Unmarshal(buf, &jsonPrefix)
	if err != nil {
		return nil, err
	}

	root, err := deserializePrefixInternalNode(jsonPrefix.Root)
	if err != nil {
		return nil, err
	}

	return &prefixTree{
		root:       root,
		isComplete: jsonPrefix.IsComplete,
	}, nil
}

//*******************************
// MERKLE NODE METHODS
//*******************************

func deserializeLeafNode(buf []byte) (*LeafNode, error) {

	var jsonLeaf JSONLeafNode
	err := json.Unmarshal(buf, &jsonLeaf)

	if err != nil {
		return &LeafNode{}, err
	}

	return &LeafNode{
		node: node{
			hash:      jsonLeaf.Hash,
			isRight:   jsonLeaf.IsRight,
			completed: jsonLeaf.Completed,
			index: index{
				depth: uint32(jsonLeaf.Depth),
				shift: uint32(jsonLeaf.Shift),
			},
		},
		contentHash: jsonLeaf.ContentHash,
		key:         jsonLeaf.Key,
	}, nil
}

func deserializeInternalNode(buf []byte) (*InternalNode, error) {

	var jsonInternal JSONInternalNode
	err := json.Unmarshal(buf, &jsonInternal)

	if err != nil {
		return &InternalNode{}, err
	}

	var leftChild MerkleNode
	if jsonInternal.LeftChild != nil && jsonInternal.Depth == 1 {
		leftChild, err = deserializeLeafNode(jsonInternal.LeftChild)
	} else if jsonInternal.LeftChild != nil {
		leftChild, err = deserializeInternalNode(jsonInternal.LeftChild)
	}

	var rightChild MerkleNode
	if jsonInternal.RightChild != nil && jsonInternal.Depth == 1 {
		rightChild, err = deserializeLeafNode(jsonInternal.RightChild)
	} else if jsonInternal.RightChild != nil {
		rightChild, err = deserializeInternalNode(jsonInternal.RightChild)
	}

	prefixTree, err := deserializePrefixTree(jsonInternal.PrefixTree)
	if err != nil {
		return nil, err
	}

	res := &InternalNode{
		node: node{
			hash:      jsonInternal.Hash,
			isRight:   jsonInternal.IsRight,
			completed: jsonInternal.Completed,
			index: index{
				depth: uint32(jsonInternal.Depth),
				shift: uint32(jsonInternal.Shift),
			},
		},
		leftChild:  leftChild,
		rightChild: rightChild,
		prefixTree: prefixTree,
	}

	if leftChild != nil {
		leftChild.setParent(res)
	}

	if rightChild != nil {
		rightChild.setParent(res)
	}

	return res, nil
}

func (node *LeafNode) serialize() ([]byte, error) {

	jsonLeaf := NewJSONLeaf(node)
	b, err := json.Marshal(jsonLeaf)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (node *InternalNode) serialize() ([]byte, error) {

	var leftChild []byte
	if node.getLeftChild() != nil {
		leftChild, _ = node.getLeftChild().serialize()
	}

	var rightChild []byte
	if node.getRightChild() != nil {
		rightChild, _ = node.getRightChild().serialize()
	}

	prefixTree, err := node.getPrefixTree().serialize()
	if err != nil {
		return nil, err
	}

	jsonInternal := NewJSONInternal(node, leftChild, rightChild, prefixTree)
	b, err := json.Marshal(jsonInternal)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// NewJSONLeaf is a factory method for JSONLeafNode structs
func NewJSONLeaf(node *LeafNode) JSONLeafNode {
	return JSONLeafNode{
		node.hash,
		node.isRight,
		node.completed,
		int(node.getDepth()),
		int(node.getShift()),
		node.contentHash,
		node.key,
	}
}

// NewJSONInternal is a factory method for JSONInternalNode structs
func NewJSONInternal(node *InternalNode, leftChild []byte, rightChild []byte, prefixTree []byte) JSONInternalNode {

	return JSONInternalNode{
		node.hash,
		node.isRight,
		node.completed,
		int(node.getDepth()),
		int(node.getShift()),
		leftChild,
		rightChild,
		prefixTree,
	}
}

//*******************************
// PREFIX NODE METHODS
//*******************************

func deserializePrefixLeafNode(buf []byte) (*leafNode, error) {

	var jsonLeaf JSONPrefixLeafNode
	err := json.Unmarshal(buf, &jsonLeaf)
	if err != nil {
		return &leafNode{}, err
	}

	var values []KeyHash
	err = json.Unmarshal(jsonLeaf.Values, &values)
	if err != nil {
		return &leafNode{}, err
	}

	return &leafNode{
		hash:          jsonLeaf.Hash,
		values:        values,
		partialPrefix: jsonLeaf.PartialPrefix,
	}, nil
}

func deserializePrefixInternalNode(buf []byte) (*internalNode, error) {

	var jsonInternal JSONPrefixInternalNode
	err := json.Unmarshal(buf, &jsonInternal)

	if err != nil {
		return &internalNode{}, err
	}

	var leftChild prefixNode
	if jsonInternal.LeftChild != nil && jsonInternal.LeftLeaf {

		leftChild, err = deserializePrefixLeafNode(jsonInternal.LeftChild)
		if err != nil {
			return nil, err
		}
	} else if jsonInternal.LeftChild != nil && !jsonInternal.LeftLeaf {

		leftChild, err = deserializePrefixInternalNode(jsonInternal.LeftChild)
		if err != nil {
			return nil, err
		}
	}

	var rightChild prefixNode
	if jsonInternal.RightChild != nil && jsonInternal.RightLeaf {

		rightChild, err = deserializePrefixLeafNode(jsonInternal.RightChild)
		if err != nil {
			return nil, err
		}
	} else if jsonInternal.RightChild != nil && !jsonInternal.RightLeaf {
		rightChild, err = deserializePrefixInternalNode(jsonInternal.RightChild)
		if err != nil {
			return nil, err
		}
	}

	res := &internalNode{
		hash:          jsonInternal.Hash,
		leftChild:     leftChild,
		rightChild:    rightChild,
		partialPrefix: jsonInternal.PartialPrefix,
	}

	if leftChild != nil {
		leftChild.setParent(res)
	}

	if rightChild != nil {
		rightChild.setParent(res)
	}

	return res, nil
}

func (node *leafNode) serialize() ([]byte, error) {

	jsonLeaf := NewJSONPrefixLeaf(node)
	b, err := json.Marshal(jsonLeaf)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (node *internalNode) serialize() ([]byte, error) {

	var leftChild []byte
	var leftChildLeaf bool
	if node.getLeftChild() != nil {
		leftChild, _ = node.getLeftChild().serialize()
		leftChildLeaf = node.getLeftChild().isLeafNode()
	}

	var rightChild []byte
	var rightChildLeaf bool
	if node.getRightChild() != nil {
		rightChild, _ = node.getRightChild().serialize()
		rightChildLeaf = node.getRightChild().isLeafNode()
	}

	jsonInternal := NewJSONPrefixInternal(node, leftChild, rightChild, leftChildLeaf, rightChildLeaf)
	b, err := json.Marshal(jsonInternal)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// NewJSONPrefixLeaf is a factory method for JSONPrefixLeaf structs
func NewJSONPrefixLeaf(node *leafNode) JSONPrefixLeafNode {

	values, _ := json.Marshal(node.getValues())

	return JSONPrefixLeafNode{
		node.getHash(),
		values,
		node.getPartialPrefix(),
	}
}

// NewJSONPrefixInternal is a factory method for JSONPrefixInternal structs
func NewJSONPrefixInternal(node *internalNode, leftChild []byte, rightChild []byte, left bool, right bool) JSONPrefixInternalNode {
	return JSONPrefixInternalNode{
		node.hash,
		leftChild,
		rightChild,
		node.getPartialPrefix(),
		left,
		right,
	}
}
