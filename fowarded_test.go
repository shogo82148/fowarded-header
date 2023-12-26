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
			name:    "empty",
			headers: []string{},
			want:    []*Forwarded{},
		},
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
