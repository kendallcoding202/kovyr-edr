package sample

import (
	"context"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/proof/pack"
)

func TestGenuineWorldVerifies(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	w, err := Build(ctx, k, Genuine)
	if err != nil {
		t.Fatal(err)
	}
	p, err := w.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r := pack.Verify(p, w.Trust)
	t.Log(r.Text())
	if !r.Verified {
		t.Fatal("genuine pack failed")
	}
}

var ctx = context.Background()
