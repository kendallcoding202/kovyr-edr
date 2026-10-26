package canon

import "testing"

func TestEncodeSortsAndCompacts(t *testing.T) {
	v := map[string]any{
		"b": int64(2),
		"a": []any{true, false, "x"},
		"_": map[string]any{"z": int64(-5), "y": ""},
	}
	got := string(MustEncode(v))
	want := `{"_":{"y":"","z":-5},"a":[true,false,"x"],"b":2}`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestParseAcceptsCanonical(t *testing.T) {
	in := `{"a":1,"b":[{"c":"d"}],"e":false}`
	if _, err := Parse([]byte(in)); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	cases := map[string]string{
		"whitespace":        `{"a": 1}`,
		"unsorted":          `{"b":1,"a":2}`,
		"duplicate":         `{"a":1,"a":1}`,
		"float":             `{"a":1.0}`,
		"exponent":          `{"a":1e3}`,
		"leading zero":      `{"a":01}`,
		"negative zero":     `{"a":-0}`,
		"null":              `{"a":null}`,
		"escape":            `{"a":"\u0041"}`,
		"escaped quote":     `{"a":"\""}`,
		"non-ascii":         `{"a":"é"}`,
		"control char":      "{\"a\":\"\t\"}",
		"too big":           `{"a":9007199254740992}`,
		"trailing data":     `{"a":1}{}`,
		"trailing newline":  "{\"a\":1}\n",
		"empty key":         `{"":1}`,
		"invalid utf8":      "{\"a\":\"\xff\"}",
		"backslash in key":  `{"a\\b":1}`,
		"case-variant dups": `{"A":1,"a":1}`, // fine as data, but unsorted? no: "A"<"a" so sorted; see below
	}
	for name, in := range cases {
		_, err := Parse([]byte(in))
		if name == "case-variant dups" {
			// Distinct keys that differ only in case are distinct keys in
			// this format; parsers must never fold case.
			if err != nil {
				t.Errorf("%s: unexpected error %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: %q was accepted", name, in)
		}
	}
}

func TestContainerIsStrictButAllowsUnicode(t *testing.T) {
	if _, err := ParseContainer([]byte(`{"name":"Müller \u0026 Co","n":3}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1.5}`, `{"a":null}`, `[1] [2]`} {
		if _, err := ParseContainer([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestEncodeRejectsForbiddenTypes(t *testing.T) {
	for _, v := range []any{3.5, nil, float32(1), map[string]any{"a": nil}, "line\nbreak", "quote\"", uint64(1)} {
		if _, err := Encode(v); err == nil {
			t.Errorf("%#v accepted", v)
		}
	}
	deep := any(int64(1))
	for i := 0; i < 40; i++ {
		deep = []any{deep}
	}
	if _, err := Encode(deep); err == nil {
		t.Error("deep nesting accepted")
	}
}
