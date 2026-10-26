package merkle

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// The RFC 6962 reference leaves used by Certificate Transparency's test
// suites, with the published roots for each prefix size.
var refLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}

var refRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func refTree(t *testing.T) *Tree {
	tr := NewTree()
	for _, l := range refLeaves {
		b, err := hex.DecodeString(l)
		if err != nil {
			t.Fatal(err)
		}
		tr.Append(LeafHash(b))
	}
	return tr
}

func TestReferenceRoots(t *testing.T) {
	tr := refTree(t)
	for i, want := range refRoots {
		got, _ := tr.Root(uint64(i + 1))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("size %d: root %x want %s", i+1, got, want)
		}
	}
	if e := EmptyRoot(); hex.EncodeToString(e[:]) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Error("empty root")
	}
}

// Exhaustively generate and verify every proof for trees up to 70 leaves,
// and check that each proof fails when anything about it is wrong.
func TestAllProofs(t *testing.T) {
	tr := NewTree()
	for i := 0; i < 70; i++ {
		tr.Append(LeafHash([]byte(fmt.Sprintf("leaf %d", i))))
	}
	for n := uint64(1); n <= tr.Size(); n++ {
		root, _ := tr.Root(n)
		for i := uint64(0); i < n; i++ {
			p, err := tr.InclusionProof(i, n)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(i, n, tr.LeafHashAt(i), p, root); err != nil {
				t.Fatalf("inclusion %d/%d: %v", i, n, err)
			}
			if VerifyInclusion(i, n, LeafHash([]byte("other")), p, root) == nil {
				t.Fatalf("inclusion %d/%d accepted a different leaf", i, n)
			}
			if n > 1 && VerifyInclusion((i+1)%n, n, tr.LeafHashAt(i), p, root) == nil && tr.LeafHashAt(i) != tr.LeafHashAt((i+1)%n) {
				t.Fatalf("inclusion %d/%d accepted a wrong index", i, n)
			}
			if len(p) > 0 {
				bad := append([]Hash(nil), p...)
				bad[0][0] ^= 1
				if VerifyInclusion(i, n, tr.LeafHashAt(i), bad, root) == nil {
					t.Fatalf("inclusion %d/%d accepted a corrupted proof", i, n)
				}
			}
		}
		for m := uint64(1); m <= n; m++ {
			rm, _ := tr.Root(m)
			p, err := tr.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(m, n, p, rm, root); err != nil {
				t.Fatalf("consistency %d->%d: %v", m, n, err)
			}
			if m < n {
				wrong := rm
				wrong[3] ^= 0x40
				if VerifyConsistency(m, n, p, wrong, root) == nil {
					t.Fatalf("consistency %d->%d accepted a wrong old root", m, n)
				}
			}
		}
	}
}

// A log that deletes an old entry and re-publishes cannot prove
// consistency with a checkpoint taken before the deletion.
func TestRewrittenHistoryFailsConsistency(t *testing.T) {
	honest, forked := NewTree(), NewTree()
	for i := 0; i < 40; i++ {
		h := LeafHash([]byte(fmt.Sprintf("entry %d", i)))
		honest.Append(h)
		if i != 17 {
			forked.Append(h)
		}
	}
	oldRoot, _ := honest.Root(30)
	newRoot, _ := forked.Root(forked.Size())
	p, _ := forked.ConsistencyProof(30, forked.Size())
	if VerifyConsistency(30, forked.Size(), p, oldRoot, newRoot) == nil {
		t.Fatal("forked log proved consistency with a pre-fork checkpoint")
	}
}
