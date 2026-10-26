// Package canon implements strict-json-c14n/v1, the canonical JSON form used
// for every byte string that is signed, timestamped or hashed into the log.
//
// The rules are deliberately narrower than RFC 8785 (JCS) so that any
// language can produce identical bytes with a few lines of code:
//
//   - Values are objects, arrays, strings, integers, true or false.
//     null and non-integer numbers are rejected.
//   - Integers are written in plain decimal (no sign on zero, no leading
//     zeros, no exponent) and must lie in [-(2^53-1), 2^53-1] so that
//     JavaScript doubles represent them exactly.
//   - Strings (and object keys) may contain only printable ASCII
//     (0x20-0x7E) except '"' and '\'. No escape sequence is ever needed,
//     so there is exactly one encoding of each string.
//   - Object keys are non-empty, unique and sorted by byte value.
//   - No insignificant whitespace.
//
// A payload is accepted as canonical only if re-encoding its parsed value
// reproduces the input byte for byte. That single comparison rejects
// duplicate keys, unsorted keys, whitespace, escapes and number variants.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

// Version names this canonicalization. It is recorded in Proof Packs so a
// future v2 can coexist; signed bytes are always kept verbatim.
const Version = "strict-json-c14n/v1"

// MaxSafeInt is the largest integer magnitude allowed (2^53 - 1).
const MaxSafeInt = 1<<53 - 1

// maxDepth bounds nesting so hostile input cannot exhaust the stack.
const maxDepth = 32

var (
	ErrNotCanonical = errors.New("not in canonical form (" + Version + ")")
	ErrFloat        = errors.New("non-integer numbers are not allowed")
	ErrNull         = errors.New("null is not allowed")
	ErrDuplicateKey = errors.New("duplicate object key")
)

// Object is the decoded form of a JSON object.
type Object = map[string]any

// Encode returns the canonical bytes of v. Accepted Go types are
// map[string]any, []any, string, bool, int, int64 and uint32.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustEncode is Encode for values built by this module's own code, where an
// error means a programming bug.
func MustEncode(v any) []byte {
	b, err := Encode(v)
	if err != nil {
		panic("canon: " + err.Error())
	}
	return b
}

func encode(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return errors.New("nesting too deep")
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if err := CheckString(k); err != nil {
				return fmt.Errorf("key %q: %w", k, err)
			}
			if k == "" {
				return errors.New("empty object key")
			}
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order; keys are ASCII
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('"')
			buf.WriteString(k)
			buf.WriteString(`":`)
			if err := encode(buf, x[k], depth+1); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e, depth+1); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
		buf.WriteByte(']')
	case string:
		if err := CheckString(x); err != nil {
			return err
		}
		buf.WriteByte('"')
		buf.WriteString(x)
		buf.WriteByte('"')
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		return encodeInt(buf, int64(x))
	case int64:
		return encodeInt(buf, x)
	case uint32:
		return encodeInt(buf, int64(x))
	case nil:
		return ErrNull
	case float32, float64, json.Number:
		return ErrFloat
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func encodeInt(buf *bytes.Buffer, n int64) error {
	if n > MaxSafeInt || n < -MaxSafeInt {
		return fmt.Errorf("integer %d outside the safe range", n)
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// CheckString enforces the canonical string alphabet.
func CheckString(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("character 0x%02x at offset %d is outside the canonical string alphabet", c, i)
		}
	}
	return nil
}

// Parse decodes b and requires it to be exactly canonical.
func Parse(b []byte) (any, error) {
	v, err := ParseContainer(b)
	if err != nil {
		return nil, err
	}
	enc, err := Encode(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(enc, b) {
		return nil, ErrNotCanonical
	}
	return v, nil
}

// ParseObject is Parse for inputs that must be a JSON object.
func ParseObject(b []byte) (Object, error) {
	v, err := Parse(b)
	if err != nil {
		return nil, err
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("top-level value must be an object")
	}
	return o, nil
}

// Canonicalize parses arbitrary (strict) JSON and returns its canonical
// encoding. It is used for objects embedded in containers such as a Proof
// Pack, whose own formatting is not significant.
func Canonicalize(b []byte) ([]byte, error) {
	v, err := ParseContainer(b)
	if err != nil {
		return nil, err
	}
	return Encode(v)
}

// ParseContainer decodes JSON that is not itself signed (for example a
// Proof Pack file). It is still strict: input must be valid UTF-8, keys must
// be unique, numbers must be safe integers, null is rejected and nothing may
// follow the top-level value. Strings may use any JSON escape and Unicode.
func ParseContainer(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the top-level value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := make(map[string]any)
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj[k]; dup {
					return nil, fmt.Errorf("%w %q", ErrDuplicateKey, k)
				}
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[k] = v
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	case string:
		return t, nil
	case bool:
		return t, nil
	case json.Number:
		return parseInt(string(t))
	case nil:
		return nil, ErrNull
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

func parseInt(s string) (int64, error) {
	// Plain decimal integers only: optional '-', then 0 or [1-9][0-9]*.
	body := s
	if len(body) > 0 && body[0] == '-' {
		body = body[1:]
	}
	if body == "" {
		return 0, ErrFloat
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return 0, fmt.Errorf("%w: %s", ErrFloat, s)
		}
	}
	if len(body) > 1 && body[0] == '0' {
		return 0, fmt.Errorf("leading zero in %s", s)
	}
	if len(body) > 16 {
		return 0, fmt.Errorf("integer %s outside the safe range", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > MaxSafeInt || n < -MaxSafeInt {
		return 0, fmt.Errorf("integer %s outside the safe range", s)
	}
	if s == "-0" {
		return 0, errors.New("negative zero is not allowed")
	}
	return n, nil
}
