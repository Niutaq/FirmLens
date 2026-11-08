# Detection Policy & Transparent Classification

FirmLens uses deterministic lexical and contextual rules (`ruleset_version = "2"`) to identify embedded credentials and selected unsafe IoT configurations without executing firmware, invoking external LLMs, or relying on opaque entropy-only heuristics.

## 1. Rule Catalog (`FL001`–`FL012`)

| Rule ID | Category | Default Severity | Redacted Evidence Format | Subject |
| --- | --- | --- | --- | --- |
| `FL001` | `hardcoded_password` | `high` | `password = [REDACTED]` | Literal password assignments |
| `FL002` | `mqtt_credentials` | `high` | `MQTT credential = [REDACTED]` | MQTT credential assignments |
| `FL003` | `private_key` | `high` (`info` for hints) | `private key material = [REDACTED]` | TLS/private-key PEM structure; incomplete markers are hints |
| `FL004` | `api_token` | `high` | `API token = [REDACTED]` | API tokens/keys |
| `FL005` | `generic_credential` | `medium` | `credential = [REDACTED]` | Generic secret/credential assignments |
| `FL006` | `authenticated_connection_string` | `high` | `authenticated URI = [REDACTED]` | Authenticated URI user information |
| `FL007` | `insecure_configuration` | `medium` | `TLS verification = disabled` | TLS verification explicitly disabled |
| `FL008` | `insecure_configuration` | `medium` | `anonymous access = enabled` | Anonymous access explicitly enabled |
| `FL009` | `sensitive_configuration` | `medium` | `SNMP community = [REDACTED]` | SNMP community strings |
| `FL010` | `cloud_device_credential` | `high` | `cloud device credential = [REDACTED]` | Device-to-cloud authentication credentials |
| `FL011` | `provisioning_credential` | `high` | `provisioning credential = [REDACTED]` | Provisioning/bootstrap credentials |
| `FL012` | `service_account_credential` | `high` | `service account credential = [REDACTED]` | Embedded service-account credentials |

## 2. Candidate Statuses & Policy Points

Every evaluated candidate receives an integer `policy_points` total summed from explicit `EvidenceSignal` records (`name`, `points`, `detail`) and is assigned one of four statuses (`CandidateStatus`):

- `confirmed_by_structural_rule` — Complete syntactic structure matched (e.g., PEM private key block header + body + footer, RFC URI userinfo with non-placeholder password, or explicit unsafe boolean toggle). Structural confirmation means syntax was matched, not that a credential works against a live service.
- `likely_secret` — Strong contextual key and literal secret characteristics (`policy_points >= 60`).
- `requires_review` — Ambiguous credential-like assignment (`35 <= policy_points < 60`) requiring analyst inspection, or informational hint (`kind = "hint"`).
- `benign_or_suppressed` — Suppressed candidate stored in `suppressed` with an explicit `suppression_reason` (e.g., `placeholder_or_template_value`, `environment_or_external_reference`, `public_certificate_or_key`, `non_secret_identifier_or_endpoint`, `safe_configuration_setting`).

## 3. Redaction by Construction

Original secret literals, URI passwords, and private key bodies are **never** stored in `Finding` or `SuppressedCandidate`. Only the fixed redacted string from `RuleMetadata::redacted_evidence` (or `<key> = [REDACTED-SUPPRESSED]`) is retained in `evidence`.

## 4. Lexical Limitations

- Inline `#` and `;` comments are stripped only outside single/double quotes when preceded by whitespace.
- Multiline templating, complex YAML anchors, UTF-16LE/BE blobs, and dynamically computed secrets are not parsed.
- Placeholder suppression (`changeme`, `example`, `${ENV_VAR}`) can suppress weak deployed defaults if an integrator ships template placeholders unchanged in production.
