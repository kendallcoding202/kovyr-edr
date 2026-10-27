package proof

import (
	"crypto/rand"
	"errors"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/posture"
)

// The statement schema is SPEC section 6.5, as data in the shared library
// (posture.EndpointPredicateSpec). The builder checks its own output
// against exactly the schema every verifier and the ingest server use, so
// the agent cannot drift from the specification: there is no second copy
// of the rules here.

// Rule is the one-line privacy rule, quoted in error messages.
const Rule = posture.Rule

// errNotEndpoint means a valid statement of another predicate type.
var errNotEndpoint = errors.New("predicateType: not an endpoint/v1 statement")

// checkStatement validates a decoded heartbeat statement against SPEC 6.5.
func checkStatement(obj map[string]any) error {
	st, err := posture.ValidateValue(obj)
	if err != nil {
		return err
	}
	if !st.IsEndpoint() {
		return errNotEndpoint
	}
	return nil
}

// parseStatement requires canonical bytes and checks them.
func parseStatement(payload []byte) (map[string]any, error) {
	obj, err := canon.ParseObject(payload)
	if err != nil {
		return nil, err
	}
	if err := checkStatement(obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// NewSalt returns 256 fresh random bits. Every statement needs its own
// salt so that its log commitment cannot be found by guessing the few
// booleans and counts inside.
func NewSalt() (Salt, error) {
	var s Salt
	_, err := rand.Read(s[:])
	return s, err
}

// NewAgentNonce returns a random nonce. Statements always carry a server
// nonce (SPEC 8); this is for previews and tests.
func NewAgentNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}
