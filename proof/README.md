# proof: the Kovyr proof library

The Go proof engine that the agent (`cmd/kovyr-agent`) and the dev receiver
(`cmd/kovyr-receiver-dev`) share: canonical JSON, DSSE envelopes, ES256 and
Ed25519 signatures, the statement schema and validator, the transparency
log, witnesses, timestamps and the Proof Pack verifier. Standard library
only.

[SPEC.md](SPEC.md) specifies the bytes. **This copy is canonical**: change
SPEC.md first, then the code and the vectors.

## Where it came from

Imported as-is from
`kendallcoding202.github.io/proof-of-protection/engine` at commit `3a2773b`
(the first commit touching `proof/` in this repo). The only edit in that
import was the import path (`proofengine/...` became
`github.com/kendallcoding202/kovyr-edr/proof/...`). Every later change is
its own commit.

## What was left out, and where it still lives

Neither the agent nor the receiver needs these, so they stay in
`kendallcoding202.github.io/proof-of-protection/`:

| Left out | What it is | Where it lives |
|---|---|---|
| `engine/cmd/proofctl` | the CLI (keys, ingest, pack build and verify by hand) | the website repo |
| `engine/internal/sample/demo.go`, `golden_test.go` | generator and golden check for the website's verify-and-tamper demo | the website repo; the demo itself is `demo/` there |
| `engine/python/` | the Python server-side implementation | the website repo |
| `demo/verifier/` | the in-browser JavaScript verifier | the website repo |

`internal/sample` keeps only the sample-firm builder (`world.go`,
`keys.go`, `util.go`), because the pack verifier's attack tests use it.

The Python and JavaScript implementations follow SPEC as of the import.
They do not know the changes made here since (see `git log -- proof/SPEC.md`)
until someone ports them.

## Regenerating the test vectors

The CLI that wrote `testdata/vectors` is not vendored. From the module root:

```sh
go test ./proof/internal/vectors -run TestVectorsAreUpToDate -update
```

`go test ./...` fails when the committed vectors drift from the generator.
Keys come from fixed seeds and all signatures are deterministic, so
regenerating gives identical files unless the format changed.
