# Security Policy

Quirn is a security tool, so we hold its own supply chain and code to the same
bar we test other people's LLM apps against.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub's **[Report a vulnerability](https://github.com/wroughtery/quirn/security/advisories/new)**
flow (Security → Advisories → *Report a vulnerability*). This opens a private
advisory only the maintainers can see.

Please include:

- what you found and where (file / flag / probe / the Action),
- steps to reproduce or a proof of concept,
- the impact you think it has.

You'll get an initial response within **5 business days**. We'll keep you updated
while we confirm, fix, and cut a patched release, and we'll credit you in the
advisory unless you'd rather stay anonymous.

## Scope

In scope:

- the `quirn` binary and its probes/judge,
- the GitHub Action (`action.yml`) and release workflow (binary integrity,
  provenance, checksums),
- anything that could let a scanned target, a crafted config, or a poisoned
  response execute code or exfiltrate data on the machine running quirn.

Out of scope:

- findings *produced by* quirn about a target you scanned (that's the tool
  working) — take those to the target's owner,
- results from scanning a target you do not own or are not authorized to test.

## Using quirn safely

Quirn sends adversarial payloads to an LLM endpoint. **Only run it against
endpoints and targets you own or are explicitly authorized to test.** The live
dashboard (`--dashboard`) exposes captured payloads and model replies — keep it
bound to loopback.

## Verifying a release

Every tagged release ships checksums and SLSA build provenance:

```sh
sha256sum -c checksums_sha256.txt
gh attestation verify quirn_<os>_<arch> --repo wroughtery/quirn
```
