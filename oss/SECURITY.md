# Security policy

## Reporting a vulnerability

Email a description, the affected crate, and a reproduction to the address published on the GitHub security tab for this repository. Do not open a public issue for an exploitable finding.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest tagged release of this repository | Yes |
| The default branch | Best effort |

## Defaults

The server binds to loopback unless `CONNECTOR_ADDR` says otherwise. Do not put a development auth bypass on a reachable network. Keep provider API keys in the environment, not in the repository.
