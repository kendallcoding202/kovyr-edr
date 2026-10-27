//go:build !windows

package sysload

// System is this machine's Source. Outside Windows (development only)
// neither condition is read, so the agent never backs off.
func System() Source { return otherSource{} }

type otherSource struct{}

func (otherSource) OnBattery() (bool, error)    { return false, ErrUnknown }
func (otherSource) CPUTimes() (CPUTimes, error) { return CPUTimes{}, ErrUnknown }
