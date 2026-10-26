package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/proof/canon"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
	"github.com/kendallcoding202/kovyr-edr/proof/tsa"
)

// ContentError explains why a statement was rejected, with the JSON path of
// the offending value.
type ContentError struct {
	Path   string
	Reason string
}

func (e *ContentError) Error() string {
	if e.Path == "" {
		return e.Reason
	}
	return e.Path + ": " + e.Reason
}

// Rule is the one-line privacy rule, quoted in error messages.
const Rule = "statements may carry only yes/no values, counts, enums and timestamps"

func fail(path, format string, a ...any) error {
	return &ContentError{Path: path, Reason: fmt.Sprintf(format, a...)}
}

// Check validates a decoded value against a spec.
func Check(v any, s *Spec, path string) error {
	switch s.T {
	case "bool":
		if _, ok := v.(bool); !ok {
			return fail(path, "must be true or false (%s)", Rule)
		}
	case "int":
		n, ok := v.(int64)
		if !ok {
			return fail(path, "must be an integer (%s)", Rule)
		}
		if (s.Min != nil && n < *s.Min) || (s.Max != nil && n > *s.Max) {
			return fail(path, "integer %d is outside the allowed range %d..%d", n, *s.Min, *s.Max)
		}
	case "enum":
		str, ok := v.(string)
		if !ok || !contains(s.Values, str) {
			return fail(path, "must be one of %s (%s)", strings.Join(s.Values, ", "), Rule)
		}
	case "const":
		if str, ok := v.(string); !ok || str != s.Value {
			return fail(path, "must be %q", s.Value)
		}
	case "timestamp":
		str, ok := v.(string)
		if !ok {
			return fail(path, "must be a UTC timestamp like 2026-10-01T14:00:00Z")
		}
		if _, err := tsa.ParseTime(str); err != nil {
			return fail(path, "must be a UTC timestamp like 2026-10-01T14:00:00Z")
		}
	case "hex":
		str, ok := v.(string)
		if !ok || len(str) != s.Len || !isLowerHex(str) {
			return fail(path, "must be %d lowercase hex characters", s.Len)
		}
	case "id":
		str, ok := v.(string)
		if !ok || !validID(str, s.Prefixes) {
			return fail(path, "must be a key-derived identifier (%s followed by 16 hex characters)", strings.Join(s.Prefixes, "/"))
		}
	case "spki":
		str, ok := v.(string)
		if !ok {
			return fail(path, "must be a base64 public key")
		}
		if _, err := sigs.ParsePublicKeyBase64(str); err != nil {
			return fail(path, "must be a canonical P-256 or Ed25519 public key: %v", err)
		}
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return fail(path, "must be an array")
		}
		if len(arr) < s.MinItems || len(arr) > s.MaxItems {
			return fail(path, "must have %d to %d items", s.MinItems, s.MaxItems)
		}
		for i, e := range arr {
			if err := Check(e, s.Of, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case "counted_list":
		return checkCountedList(v, s, path)
	case "result_list":
		return checkResultList(v, s, path)
	case "object":
		return checkObject(v, s, path)
	default:
		return fail(path, "schema error: unknown type %q", s.T)
	}
	return nil
}

func checkObject(v any, s *Spec, path string) error {
	o, ok := v.(map[string]any)
	if !ok {
		return fail(path, "must be an object")
	}
	fields := make(map[string]*Spec, len(s.Fields))
	for k, f := range s.Fields {
		fields[k] = f
	}
	if s.Switch != nil {
		tag, _ := o[s.Switch.On].(string)
		extra, ok := s.Switch.Cases[tag]
		if !ok {
			if err := Check(o[s.Switch.On], s.Fields[s.Switch.On], join(path, s.Switch.On)); err != nil {
				return err
			}
			return fail(join(path, s.Switch.On), "unsupported value %q", tag)
		}
		for k, f := range extra {
			fields[k] = f
		}
	}
	// Unknown fields first: this is where a smuggled "hostname" or "path"
	// is caught, and the message should say so plainly.
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := fields[k]; !ok {
			return fail(join(path, k), "field is not allowed (%s)", Rule)
		}
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		val, ok := o[k]
		if !ok {
			return fail(join(path, k), "required field is missing")
		}
		if err := Check(val, fields[k], join(path, k)); err != nil {
			return err
		}
	}
	for _, le := range s.LE {
		a, _ := o[le[0]].(int64)
		b, _ := o[le[1]].(int64)
		if a > b {
			return fail(join(path, le[0]), "must not exceed %s (%d > %d)", le[1], a, b)
		}
	}
	return nil
}

func checkCountedList(v any, s *Spec, path string) error {
	o, ok := v.(map[string]any)
	if !ok || len(o) != 3 {
		return fail(path, "must be {items, total, truncated}")
	}
	items, ok1 := o["items"].([]any)
	total, ok2 := o["total"].(int64)
	truncated, ok3 := o["truncated"].(bool)
	if !ok1 || !ok2 || !ok3 {
		return fail(path, "must be {items: array, total: integer, truncated: true/false}")
	}
	if len(items) > s.MaxItems {
		return fail(join(path, "items"), "at most %d items are allowed; set truncated instead", s.MaxItems)
	}
	if total < 0 || total > s.MaxCount*int64(len(s.Kinds)) {
		return fail(join(path, "total"), "out of range")
	}
	var sum int64
	prev := ""
	for i, it := range items {
		ip := fmt.Sprintf("%s.items[%d]", path, i)
		io, ok := it.(map[string]any)
		if !ok || len(io) != 2 {
			return fail(ip, "must be exactly {count, kind} (%s)", Rule)
		}
		kind, ok := io["kind"].(string)
		if !ok || !contains(s.Kinds, kind) {
			return fail(join(ip, "kind"), "must be one of %s (%s)", strings.Join(s.Kinds, ", "), Rule)
		}
		n, ok := io["count"].(int64)
		if !ok || n < 1 || n > s.MaxCount {
			return fail(join(ip, "count"), "must be an integer 1..%d", s.MaxCount)
		}
		if kind <= prev {
			return fail(ip, "items must be sorted by kind with no repeats")
		}
		prev = kind
		sum += n
	}
	if !truncated && sum != total {
		return fail(join(path, "total"), "must equal the sum of item counts when truncated is false")
	}
	if truncated && (len(items) != s.MaxItems || sum >= total) {
		return fail(join(path, "truncated"), "truncated lists must be full and total must exceed the listed counts")
	}
	return nil
}

func checkResultList(v any, s *Spec, path string) error {
	o, ok := v.(map[string]any)
	if !ok || len(o) != 3 {
		return fail(path, "must be {items, total, truncated}")
	}
	items, ok1 := o["items"].([]any)
	total, ok2 := o["total"].(int64)
	truncated, ok3 := o["truncated"].(bool)
	if !ok1 || !ok2 || !ok3 {
		return fail(path, "must be {items: array, total: integer, truncated: true/false}")
	}
	if len(items) > s.MaxItems {
		return fail(join(path, "items"), "at most %d items are allowed; set truncated instead", s.MaxItems)
	}
	if total < 0 || total > 1000 {
		return fail(join(path, "total"), "out of range")
	}
	prev := ""
	for i, it := range items {
		ip := fmt.Sprintf("%s.items[%d]", path, i)
		if err := Check(it, s.Of, ip); err != nil {
			return err
		}
		k := it.(map[string]any)[s.Key].(string)
		if k <= prev {
			return fail(ip, "items must be sorted by %s with no repeats", s.Key)
		}
		prev = k
	}
	n := int64(len(items))
	if !truncated && n != total {
		return fail(join(path, "total"), "must equal the number of items when truncated is false")
	}
	if truncated && (len(items) != s.MaxItems || total <= n) {
		return fail(join(path, "truncated"), "truncated lists must be full and total must exceed the number of items")
	}
	return nil
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validID(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) && len(s) == len(p)+16 && isLowerHex(s[len(p):]) {
			return true
		}
	}
	return false
}

// Statement is a validated in-toto statement.
type Statement struct {
	PredicateType string
	SubjectName   string
	SubjectDigest string
	Predicate     map[string]any
	Raw           map[string]any
}

// Validate checks that payload is a canonical in-toto statement of an
// accepted predicate type that obeys its schema.
func Validate(payload []byte) (*Statement, error) {
	obj, err := canon.ParseObject(payload)
	if err != nil {
		return nil, &ContentError{Reason: err.Error()}
	}
	return ValidateValue(obj)
}

// ValidateValue is Validate for an already-decoded value (used by the
// builder to check its own output).
func ValidateValue(obj map[string]any) (*Statement, error) {
	pt, _ := obj["predicateType"].(string)
	spec, ok := Schemas()[pt]
	if !ok {
		return nil, fail("predicateType", "unsupported predicate type %q", pt)
	}
	if err := Check(obj, spec, ""); err != nil {
		return nil, err
	}
	subj := obj["subject"].([]any)[0].(map[string]any)
	st := &Statement{
		PredicateType: pt,
		SubjectName:   subj["name"].(string),
		SubjectDigest: subj["digest"].(map[string]any)["sha256"].(string),
		Predicate:     obj["predicate"].(map[string]any),
		Raw:           obj,
	}
	// The subject is the attester itself (posture) or the enrolled key.
	switch pt {
	case PosturePredicateType():
		if st.SubjectName != st.Str("attester") {
			return nil, fail("subject[0].name", "must equal predicate.attester")
		}
		if !strings.HasPrefix(st.Str("attester"), prefixForKind(st.Str("attester_kind"))) {
			return nil, fail("predicate.attester", "prefix does not match attester_kind")
		}
	case EndpointPredicateType():
		// No enrollment binds the key yet (SPEC 6.5), so the device ID
		// must be derived from the signing key named in the subject.
		if st.SubjectName != st.Str("attester") {
			return nil, fail("subject[0].name", "must equal predicate.attester")
		}
		if st.Str("attester") != PrefixDevice+st.SubjectDigest[:16] {
			return nil, fail("predicate.attester", "must be derived from the key in subject[0].digest")
		}
	case EnrollmentPredicateType():
		want := st.Str("tenant")
		if st.Str("kind") == "attester" {
			want = st.Str("attester")
			if !strings.HasPrefix(want, prefixForKind(st.Str("attester_kind"))) {
				return nil, fail("predicate.attester", "prefix does not match attester_kind")
			}
		}
		if st.SubjectName != want {
			return nil, fail("subject[0].name", "must name the enrolled tenant or attester")
		}
	}
	return st, nil
}

func prefixForKind(kind string) string {
	switch kind {
	case "device_agent":
		return PrefixDevice
	case "cloud_connector":
		return PrefixConnector
	case "staff_attester":
		return PrefixStaff
	case "external_scanner":
		return PrefixScanner
	}
	return "\x00"
}

// Str returns a string predicate field by path ("device.edr_kind").
func (s *Statement) Str(path string) string { v, _ := s.get(path).(string); return v }

// Int returns an integer predicate field by path.
func (s *Statement) Int(path string) int64 { v, _ := s.get(path).(int64); return v }

// Bool returns a boolean predicate field by path.
func (s *Statement) Bool(path string) bool { v, _ := s.get(path).(bool); return v }

// Time returns a timestamp predicate field by path.
func (s *Statement) Time(path string) time.Time {
	t, _ := tsa.ParseTime(s.Str(path))
	return t
}

// Get returns any predicate field by path.
func (s *Statement) Get(path string) any { return s.get(path) }

func (s *Statement) get(path string) any {
	var cur any = s.Predicate
	for _, p := range strings.Split(path, ".") {
		o, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = o[p]
	}
	return cur
}

// IsPosture reports whether this is a posture statement.
func (s *Statement) IsPosture() bool { return s.PredicateType == PosturePredicateType() }

// IsEndpoint reports whether this is an endpoint agent's heartbeat
// (SPEC 6.5).
func (s *Statement) IsEndpoint() bool { return s.PredicateType == EndpointPredicateType() }

// PosturePredicateType and EnrollmentPredicateType expose the brand
// constants under stable names.
func PosturePredicateType() string    { return brandPosture }
func EnrollmentPredicateType() string { return brandEnrollment }
func EndpointPredicateType() string   { return brandEndpoint }
