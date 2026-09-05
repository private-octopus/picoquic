# WebTransport Conformance Tests

This document tracks picoquic's in-tree WebTransport-over-HTTP/3 tests. The
generic browser and WPT harnesses live outside this repository in
`h3browserconformance`; that repository also carries the expanded conformance
`pico_baton` server used by the external suite.

## In-Tree Test Labels

| Label | Purpose |
| --- | --- |
| `wt_strict` | Native tests for WebTransport-over-HTTP/3 behavior. These tests must not depend on legacy browser tokens or settings except when asserting that strict mode rejects them. |
| `wt_compat` | Explicit browser compatibility tests that belong in picoquic because they validate picoquic protocol behavior or the small in-tree baton example. |
| `wt_wire` | Native wire-protocol and parser tests for SETTINGS, stream prefixes, capsules, datagrams, reset codes, close behavior, and exact error handling. |
| `wt_fuzz` | Fuzz and property-style tests for parsers and state-machine inputs. |

Run a label with CTest after configuring and building:

```sh
ctest --test-dir build -L wt_strict --output-on-failure
ctest --test-dir build -L wt_compat --output-on-failure
ctest --test-dir build -L wt_wire --output-on-failure
ctest --test-dir build -L wt_fuzz --output-on-failure
```

The picoquic CI gate checks the external WPT adapter manifests, dry-run wiring,
and server smoke against the small in-tree `pico_baton`. Full browser smoke and
manifest-driven browser E2E are run from `h3browserconformance`, where browser
draft-compatibility expectations and the expanded conformance server live.

## Strict Versus Compatibility Mode

Strict mode is the WebTransport conformance target. Strict WebTransport tests
should use the native HTTP/3 WebTransport token `webtransport-h3`, require the
current SETTINGS and transport parameters, enforce CONNECT pseudo-header
requirements, and assert exact HTTP/3/WebTransport error behavior where defined.

Compatibility mode is only for browser behavior required for real
interoperability but not part of the strict path. Compatibility tests must be
labeled `wt_compat`, must not weaken strict tests, and must describe the browser
or engine behavior being accommodated.

If WebTransport production code needs a browser-specific conditional branch or
workaround, document it with an inline code comment at the workaround site. The
comment must identify the browser/version or engine behavior, explain why the
strict path is not sufficient, and point to the compatibility test or artifact
that proves the exception is still needed.
