package cloud

type Provider int

const (
	AWS Provider = iota
	TencentCloud
)

func (p Provider) String() string {
	return [...]string{"AWS", "TencentCloud"}[p]
}
