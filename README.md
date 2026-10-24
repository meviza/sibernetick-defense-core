# Sibernetick Defense Core

A first, deliberately scoped open-source release of reusable defensive components from Project Keymaker, maintained personally by Kerem Çelik. MIT licensed.

## Included

- Per-tenant token-bucket rate-limiting primitives and Starlette middleware.
- A heuristic data-governance service with a storage interface and synthetic tests.
- A browser-extension permission-combination risk checker.
- An authorized-target profile data structure.

This repository contains actual extracted source, not the marketing website. It is **not the complete Keymaker platform**. Platform databases, credentials, private reports, operational tooling, and the original Git history are not part of this release. No offensive execution tooling is included.

## Run the checks

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

## Limitations

This is a development baseline, not a certified security product. Secret/prompt-injection checks are incomplete heuristics and must not be relied on for comprehensive redaction or prevention. The limiter stores state in process memory, not a shared distributed store. Its header-based tenant fallback must only be used behind a trusted authentication boundary that strips untrusted tenant headers. The authorized-target dataclass records metadata; it does not verify authorization. The permission checker matches only its documented combinations and is not a complete browser-extension audit.

## Roadmap

Broaden negative tests; define deployment-safe integration boundaries; document limitations with reproducible examples; add cost-bounded AI-assisted contributor and review workflows. No adoption, independent security certification, or grant award is claimed.

See CONTRIBUTING.md, SECURITY.md and SOURCE_PROVENANCE.json.
