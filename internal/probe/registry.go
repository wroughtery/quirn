package probe

// All returns every probe quirn knows how to run, in a stable order. The order
// is deterministic so reports and baselines diff cleanly across runs.
func All() []Probe {
	return []Probe{
		NewInjectionProbe(), // LLM01
		NewSensitiveProbe(), // LLM02
		NewOutputProbe(),    // LLM05
		NewAgencyProbe(),    // LLM06
		NewLeakageProbe(),   // LLM07
	}
}
