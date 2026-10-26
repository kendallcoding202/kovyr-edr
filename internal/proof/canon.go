package proof

// This file ports strict-json-c14n/v1 from the Kovyr proof engine
// (proof-of-protection/engine/canon). Every byte string that is signed or
// hashed uses it.
//
// TODO(shared-lib): replace this file, sigs.go and dsse.go with the shared
// proof library once it is published as an importable module. Until then
// the test vectors in testdata/ (copied from the engine) keep the two
// implementations byte-compatible.
//
// The rules, narrower than RFC 8785 on purpose:
//   - values are objects, arrays, strings, integers, true or false;
//     null and non-integer numbers are rejected;
//   - integers are plain decimal in [-(2^53-1), 2^53-1];
//   - strings and keys use only printable ASCII 0x20-0x7E except '"' and
//     '\', so no escape is ever needed;
//   - object keys are non-empty, unique and sorted by byte value;
//   - no insignificant whitespace.
//
// Input is canonical only if re-encoding its parsed value gives the same
// bytes, which rejects duplicate or unsorted keys, whitespace, escapes and
// number variants in one comparison.

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

// CanonVersion names the canonicalization.
const CanonVersion = "strict-json-c14n/v1"

const (
	maxSafeInt = 1<<53 - 1
	maxDepth   = 32
)

// ErrNotCanonical is returned by ParseCanonical for valid but
// non-canonical JSON.
var ErrNotCanonical = errors.New("not in canonical form (" + CanonVersion + ")")

// EncodeCanonical returns the canonical bytes of v. Accepted Go types are
// map[string]any, []any, string, bool, int and int64.
func EncodeCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return errors.New("nesting too deep")
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if k == "" {
				return errors.New("empty object key")
			}
			if err := checkCanonString(k); err != nil {
				return fmt.Errorf("key %q: %w", k, err)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('"')
			buf.WriteString(k)
			buf.WriteString(`":`)
			if err := encodeValue(buf, x[k], depth+1); err != nil {
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
			if err := encodeValue(buf, e, depth+1); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
		buf.WriteByte(']')
	case string:
		if err := checkCanonString(x); err != nil {
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
	case nil:
		return errors.New("null is not allowed")
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func encodeInt(buf *bytes.Buffer, n int64) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return fmt.Errorf("integer %d outside the safe range", n)
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func checkCanonString(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return fmt.Errorf("character 0x%02x at offset %d is outside the canonical string alphabet", c, i)
		}
	}
	return nil
}

// ParseCanonical decodes b and requires it to be exactly canonical.
func ParseCanonical(b []byte) (any, error) {
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
	enc, err := EncodeCanonical(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(enc, b) {
		return nil, ErrNotCanonical
	}
	return v, nil
}

// ParseCanonicalObject is ParseCanonical for a top-level object.
func ParseCanonicalObject(b []byte) (map[string]any, error) {
	v, err := ParseCanonical(b)
	if err != nil {
		return nil, err
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("top-level value must be an object")
	}
	return o, nil
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
			obj := map[string]any{}
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
					return nil, fmt.Errorf("duplicate object key %q", k)
				}
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[k] = v
			}
			if _, err := dec.Token(); err != nil {
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
			if _, err := dec.Token(); err != nil {
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
		return parseCanonInt(string(t))
	case nil:
		return nil, errors.New("null is not allowed")
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

func parseCanonInt(s string) (int64, error) {
	body := s
	if len(body) > 0 && body[0] == '-' {
		body = body[1:]
	}
	if body == "" || len(body) > 16 {
		return 0, fmt.Errorf("bad integer %q", s)
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return 0, fmt.Errorf("non-integer number %q is not allowed", s)
		}
	}
	if len(body) > 1 && body[0] == '0' {
		return 0, fmt.Errorf("leading zero in %s", s)
	}
	if s == "-0" {
		return 0, errors.New("negative zero is not allowed")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return 0, fmt.Errorf("integer %s outside the safe range", s)
	}
	return n, nil
}
