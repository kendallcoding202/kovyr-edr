// Package merkle implements the RFC 6962 / RFC 9162 Merkle tree: leaf and
// node hashing with domain separation, inclusion and consistency proof
// generation (RFC 6962 section 2.1), and verification (RFC 9162 sections
// 2.1.3.2 and 2.1.4.2).
package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// Hash is a SHA-256 digest.
type Hash = [32]byte

// LeafHash is SHA-256(0x00 || leaf).
func LeafHash(leaf []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(l, r Hash) Hash {
	var buf [65]byte
	buf[0] = 1
	copy(buf[1:], l[:])
	copy(buf[33:], r[:])
	return sha256.Sum256(buf[:])
}

// EmptyRoot is the root of the empty tree, SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// Tree holds leaf hashes and memoizes complete (power-of-two, aligned)
// subtrees, which never change as the tree grows.
type Tree struct {
	leaves []Hash
	memo   map[[2]uint64]Hash
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{memo: map[[2]uint64]Hash{}} }

// FromLeafHashes builds a tree from existing leaf hashes.
func FromLeafHashes(hs []Hash) *Tree {
	t := NewTree()
	t.leaves = append(t.leaves, hs...)
	return t
}

// Append adds a leaf hash and returns its index.
func (t *Tree) Append(h Hash) uint64 {
	t.leaves = append(t.leaves, h)
	return uint64(len(t.leaves) - 1)
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 { return uint64(len(t.leaves)) }

// LeafHashAt returns leaf hash i.
func (t *Tree) LeafHashAt(i uint64) Hash { return t.leaves[i] }

// Root returns the root of the first size leaves.
func (t *Tree) Root(size uint64) (Hash, error) {
	if size > t.Size() {
		return Hash{}, fmt.Errorf("size %d exceeds tree size %d", size, t.Size())
	}
	if size == 0 {
		return EmptyRoot(), nil
	}
	return t.mth(0, size), nil
}

// SubtreeRoot returns MTH(D[lo:hi]) for hi <= Size().
func (t *Tree) SubtreeRoot(lo, hi uint64) (Hash, error) {
	if lo >= hi || hi > t.Size() {
		return Hash{}, fmt.Errorf("bad subtree [%d, %d) of a tree of size %d", lo, hi, t.Size())
	}
	return t.mth(lo, hi), nil
}

// mth is MTH(D[lo:hi]).
func (t *Tree) mth(lo, hi uint64) Hash {
	n := hi - lo
	if n == 1 {
		return t.leaves[lo]
	}
	complete := n&(n-1) == 0
	if complete {
		if h, ok := t.memo[[2]uint64{lo, hi}]; ok {
			return h
		}
	}
	k := splitPoint(n)
	h := NodeHash(t.mth(lo, lo+k), t.mth(lo+k, hi))
	if complete {
		t.memo[[2]uint64{lo, hi}] = h
	}
	return h
}

// splitPoint is the largest power of two strictly less than n (n >= 2).
func splitPoint(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// InclusionProof returns PATH(index, D[0:size]).
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if size > t.Size() || index >= size {
		return nil, fmt.Errorf("no inclusion proof for index %d in tree of size %d", index, size)
	}
	return t.path(index, 0, size), nil
}

func (t *Tree) path(m, lo, hi uint64) []Hash {
	n := hi - lo
	if n == 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(t.path(m, lo, lo+k), t.mth(lo+k, hi))
	}
	return append(t.path(m-k, lo+k, hi), t.mth(lo, lo+k))
}

// ConsistencyProof returns PROOF(m, D[0:n]).
func (t *Tree) ConsistencyProof(m, n uint64) ([]Hash, error) {
	if n > t.Size() || m > n {
		return nil, fmt.Errorf("no consistency proof from %d to %d (tree size %d)", m, n, t.Size())
	}
	if m == 0 || m == n {
		return nil, nil
	}
	return t.subproof(m, 0, n, true), nil
}

func (t *Tree) subproof(m, lo, hi uint64, b bool) []Hash {
	n := hi - lo
	if m == n {
		if b {
			return nil
		}
		return []Hash{t.mth(lo, hi)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(t.subproof(m, lo, lo+k, b), t.mth(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.mth(lo, lo+k))
}

var (
	ErrInclusion   = errors.New("inclusion proof does not match the tree root")
	ErrConsistency = errors.New("consistency proof failed: the log's history was changed")
)

// VerifyInclusion implements RFC 9162 section 2.1.3.2.
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	if index >= size {
		return fmt.Errorf("leaf index %d is not below tree size %d", index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrInclusion
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrInclusion
	}
	return nil
}

// VerifyConsistency implements RFC 9162 section 2.1.4.2.
func VerifyConsistency(first, second uint64, proof []Hash, firstRoot, secondRoot Hash) error {
	switch {
	case first > second:
		return fmt.Errorf("first size %d is larger than second size %d", first, second)
	case first == second:
		if len(proof) != 0 || firstRoot != secondRoot {
			return ErrConsistency
		}
		return nil
	case first == 0:
		if len(proof) != 0 {
			return ErrConsistency
		}
		return nil
	case len(proof) == 0:
		return ErrConsistency
	}
	if first&(first-1) == 0 { // exact power of two
		proof = append([]Hash{firstRoot}, proof...)
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return ErrConsistency
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || fr != firstRoot || sr != secondRoot {
		return ErrConsistency
	}
	return nil
}
