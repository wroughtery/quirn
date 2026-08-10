package probe

// All returns every probe quirn knows how to run, in a stable order.
func All() []Probe {
	return []Probe{
		NewInjectionProbe(),
		NewLeakageProbe(),
	}
}
