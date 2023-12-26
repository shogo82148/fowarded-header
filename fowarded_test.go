package fowardedheader

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestForwarded_String(t *testing.T) {
	tests := []struct {
		name string
		f    *Forwarded
		want string
	}{
		{
			name: "empty",
			f:    &Forwarded{},
			want: "",
		},
		{
			name: "for",
			f: &Forwarded{
				For: "_gazonk",
			},
			want: `for=_gazonk`,
		},
		{
			name: "for-ipv6",
			f: &Forwarded{
				For: `[2001:db8:cafe::17]`,
			},
			want: `for="[2001:db8:cafe::17]"`,
		},
		{
			name: "for-ipv4-and-port",
			f: &Forwarded{
				For: `192.0.2.43:47011`,
			},
			want: `for="192.0.2.43:47011"`,
		},
		{
			name: "for-ipv6-and-port",
			f: &Forwarded{
				For: `[2001:db8:cafe::17]:4711`,
			},
			want: `for="[2001:db8:cafe::17]:4711"`,
		},
		{
			name: "for-ipv6-and-port-and-extensions",
			f: &Forwarded{
				For:   `192.0.2.60`,
				Proto: "http",
				By:    `203.0.113.43`,
			},
			want: `by=203.0.113.43;for=192.0.2.60;proto=http`,
		},
		{
			name: "proto-http",
			f: &Forwarded{
				Proto: "http",
			},
			want: `proto=http`,
		},
		{
			name: "proto-https",
			f: &Forwarded{
				Proto: "https",
			},
			want: `proto=https`,
		},

		// escape
		{
			name: "back-slash",
			f: &Forwarded{
				For: `\`,
			},
			want: `for="\\"`,
		},
		{
			name: "double-quote",
			f: &Forwarded{
				For: `"`,
			},
			want: `for="\""`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			if got := f.String(); got != tt.want {
				t.Errorf("Forwarded.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    []*Forwarded
	}{
		{
			name:    "empty-string",
			headers: []string{""},
			want: []*Forwarded{
				{},
			},
		},

		// Examples from RFC 7239 Section 4.
		{
			name: "for-gazonk",
			headers: []string{
				`for="_gazonk"`,
			},
			want: []*Forwarded{
				{
					For: "_gazonk",
				},
			},
		},
		{
			name: "for-ipv6",
			headers: []string{
				`For="[2001:db8:cafe::17]:4711"`,
			},
			want: []*Forwarded{
				{
					For: "[2001:db8:cafe::17]:4711",
				},
			},
		},
		{
			name: "for-and-proto",
			headers: []string{
				`for=192.0.2.60;proto=http;by=203.0.113.43`,
			},
			want: []*Forwarded{
				{
					For:   "192.0.2.60",
					Proto: "http",
					By:    "203.0.113.43",
				},
			},
		},
		{
			name: "multiple-for",
			headers: []string{
				`for=192.0.2.43, for=198.51.100.17`,
			},
			want: []*Forwarded{
				{
					For: "192.0.2.43",
				},
				{
					For: "198.51.100.17",
				},
			},
		},

		// Examples from RFC 7239 Section 7.1.
		{
			name: "rfc7239-section7-example1",
			headers: []string{
				`for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown`,
			},
			want: []*Forwarded{
				{
					For: "192.0.2.43",
				},
				{
					For: "[2001:db8:cafe::17]",
				},
				{
					For: "unknown",
				},
			},
		},
		{
			name: "rfc7239-section7-example2",
			headers: []string{
				`for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown`,
			},
			want: []*Forwarded{
				{
					For: "192.0.2.43",
				},
				{
					For: "[2001:db8:cafe::17]",
				},
				{
					For: "unknown",
				},
			},
		},
		{
			name: "rfc7239-section7-example3",
			headers: []string{
				`for=192.0.2.43`,
				`for="[2001:db8:cafe::17]", for=unknown`,
			},
			want: []*Forwarded{
				{
					For: "192.0.2.43",
				},
				{
					For: "[2001:db8:cafe::17]",
				},
				{
					For: "unknown",
				},
			},
		},

		{
			name: "unknown-key",
			headers: []string{
				`foo=bar`,
			},
			want: []*Forwarded{
				{},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.headers)
			if err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`for="_gazonk"`)
	f.Add(`For="[2001:db8:cafe::17]:4711"`)
	f.Add(`for=192.0.2.60;proto=http;by=203.0.113.43`)

	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := Parse([]string{s})
		if err != nil {
			return
		}

		encoded := Encode(parsed)

		parsed2, err := Parse([]string{encoded})
		if err != nil {
			t.Errorf("%q: %v", encoded, err)
		}

		if diff := cmp.Diff(parsed, parsed2); diff != "" {
			t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
		}
	})
}
