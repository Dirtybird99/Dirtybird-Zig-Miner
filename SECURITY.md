# Security Policy

This policy covers **Dirtybird Zig Miner** (https://github.com/Dirtybird99/Dirtybird-Zig-Miner).

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the Security tab of the [Dirtybird99/Dirtybird-Zig-Miner](https://github.com/Dirtybird99/Dirtybird-Zig-Miner/security) repository
2. **Email**: Contact the maintainer directly

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix/release**: Depends on severity

## Scope

This policy applies to the latest version of the software on the `main` branch, built
from source with Zig 0.14.1 (`zig build -Doptimize=ReleaseFast -Dcpu=native`) to produce
the `zig-miner` binary.

Please note:

- The miner requires an x86-64 CPU with the SHA-NI and AVX2 instruction sets. Reports
  about unrelated hardware or toolchain versions are out of scope.
- This is a CPU miner that connects to a DERO daemon/pool over the network. When
  reporting, please describe the configuration (daemon address, threads, and build
  flags such as `-Dpgo=use`) so the issue can be reproduced.
- Do not include real wallet addresses or private network details in public reports.
