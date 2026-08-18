package probe

// All returns every probe quirn knows how to run, in a stable order. The order
// is deterministic so reports and baselines diff cleanly across runs.
//
// Four OWASP LLM Top 10 classes are intentionally absent, not merely
// unimplemented: LLM03 (supply chain), LLM04 (data/model poisoning), LLM08
// (vector/embedding weaknesses), and LLM10 (unbounded consumption) are not
// soundly provable as a black-box probe against a raw endpoint. LLM03/LLM04
// are training- and build-time properties — no amount of prompting a live
// endpoint observes what data or dependencies it was built from. LLM08 needs
// visibility into the retrieval/embedding pipeline a bare chat endpoint
// doesn't expose. LLM10 would require judging "large/slow response" or
// "missing rate limit" from the outside, which is unobservable without a
// known-good baseline and is indistinguishable from ordinary latency or load.
// Claiming coverage of any of these from a single HTTP endpoint would be a
// false positive/negative machine, not a probe — so quirn omits them rather
// than fake a signal it can't back up.
func All() []Probe {
	return []Probe{
		NewInjectionProbe(), // LLM01
		NewSensitiveProbe(), // LLM02
		NewOutputProbe(),    // LLM05
		NewAgencyProbe(),    // LLM06
		NewLeakageProbe(),   // LLM07
		NewMisinfoProbe(),   // LLM09
	}
}
