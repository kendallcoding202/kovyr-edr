// Package brand holds every brand-dependent string in one place.
//
// The product may be renamed. Protocol identifiers that do not need a
// domain (canonicalization, entry and pack types) are deliberately
// brand-neutral and live in their own packages. Only the values below
// change on a rename; after changing them, regenerate the demo data and
// test vectors (see README.md) because statements embed the predicate
// type and checkpoints embed the log origin.
package brand

const (
	// Name is the company / brand name shown to people.
	Name = "Kovyr"

	// Product is the product name shown to people (placeholder).
	Product = "Kovyr Proof"

	// AttestationBase is the URI prefix for our in-toto predicate types.
	AttestationBase = "https://kovyr.com/attestation/"

	// PredicatePosture is the in-toto predicateType of posture statements.
	PredicatePosture = AttestationBase + "posture/v1"

	// PredicateEnrollment is the in-toto predicateType of enrollment records.
	PredicateEnrollment = AttestationBase + "enrollment/v1"

	// DemoLogOrigin is the C2SP checkpoint origin of the demo log.
	DemoLogOrigin = "kovyr.com/proof/demo-log"
)
