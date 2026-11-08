# Security boundaries

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the complete boundary, enforceable limits and remaining risks.

Only synthetic fixtures belong in this repository. Never include real firmware, credentials or keys in issues/test data. FirmLens never executes firmware. Native extraction accepts a bounded, deliberately restricted TAR/TAR.GZ subset and rejects links/special members. Other image extraction is disabled. Optional Binwalk identification runs only inside the restricted Docker invocation; there is no host-tool fallback.

Use immutable local inputs and a private temporary parent. Native deadlines are cooperative; mutable-tree races, process memory and remote filesystem blocking are not fully sandboxed. Docker runtime/image trust and OS integrity are prerequisites for the optional container boundary.

Reports redact source values by construction but retain paths, locations and categories. In-memory buffers are not zeroized. Crashes can leave temporary material; cleanup failures are explicitly reported when detected. No findings does not prove secure firmware.

The web application is for a single trusted local user. Keep both API and frontend on loopback. Host/origin/custom-header checks mitigate browser cross-origin abuse but do not authenticate local processes or provide authorization. Do not expose or reverse-proxy the API to other hosts; remote access requires a separate security design. Reports are retained in memory until eviction or restart. See [docs/WEB_APPLICATION.md](docs/WEB_APPLICATION.md) for upload limits and service behavior.

Report security issues using a minimal synthetic reproducer, version, OS and options. Do not attach production secrets. A private disclosure address or hosted reporting service is not currently advertised.
