package fowardedheader

type Forwarded struct {
	By    string
	For   string
	Host  string
	Proto string
}

func (f *Forwarded) String() string {
	return ""
}

func Parse(h []string) ([]*Forwarded, error) {
	return []*Forwarded{}, nil
}
