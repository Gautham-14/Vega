# Independent provider release evidence

A provider's self-reported digest and candidate tests do not prove loaded weights
or network isolation. INTERNAL coding/media content is withheld until the
following separately bound evidence and approvals pass.

1. The host administrator verifies and records a signed offline bundle:
   `bundle-record <directory> --trust-policy <file>`.
2. Model Custodian registers an immutable profile with the returned
   `bundle_record_id`, numeric-loopback endpoint, explicit model and digest.
3. Model Custodian runs PUBLIC candidate tests with `provider-qualify` or
   `provider-qualify-media`. Every case must pass. Qualification output contains
   only observations and hashes; raw prompts, images and model outputs are not retained.
4. An independent attestor verifies loaded weights, OS network isolation and
   disabled server retention. `provider-measure <id> <pid>` provides local
   executable/process/listener observations without claiming network isolation.
5. Security Officer imports the attestor's signed evidence using
   `provider-attest <id> evidence.json`.
6. Model Custodian and Data Owner inspect `provider-release-review <id> <candidate-id>`
   and independently approve the returned approval ID. Model Custodian then
   runs `provider-release <id> <approval-id>`.

The host administrator sets `AEGIS_PROVIDER_TRUST_POLICY` to an independently
provisioned local JSON file. Its format is:

```json
{
  "schema_version": "aegis-provider-trust-v1",
  "signers": {
    "independent-attestor": {
      "public_key_path": "C:/trusted/attestor.pem",
      "public_key_sha256": "<SHA-256 of the raw 32-byte Ed25519 public key>"
    }
  },
  "expires_at": 1900000000.0,
  "revoked_attestation_sha256": []
}
```

Public keys use PEM SubjectPublicKeyInfo. Trust files and keys must be outside
the model bundle. The attestor key must differ from the bundle publisher's key.
The server has no operation that provisions trusted attestors or creates an
attestation signature.

`evidence.json` contains `attestation` and a detached base64 `signature`.
The attestation fields are:

| Field | Binding |
| --- | --- |
| `schema_version` | `aegis-provider-attestation-v1` |
| `signer_id` | Entry in the administrator's independent trust policy |
| `provider_id`, `provider_configuration_sha256` | Immutable provider and `providers.configuration_hash(spec)` |
| `bundle_record_id`, `manifest_sha256`, `weights_inventory_sha256` | Revalidated signed bundle custody |
| `qualification_id`, `qualification_sha256` | Sealed passing candidate result and `model_qualification.qualification_hash(result)` |
| `process` | `pid`, `created_at` (Unix timestamp), `executable_sha256` from measurement |
| `loaded_weights_verified`, `network_isolation_verified`, `server_retention_disabled` | All must be `true`, asserted by the independent attestor |
| `issued_at`, `expires_at` | Unix timestamps; positive finite numbers, at most fifteen minutes apart |

Sign `offline_bundle.canonical_bytes(attestation)`: UTF-8 JSON with sorted keys,
compact separators, `ensure_ascii=False`, and no non-finite numbers. Persist the
same numeric representation in the JSON document used for signing and import.

The serving executable must match the bundle runtime hash and own the exact
configured numeric-loopback listener. Non-loopback listeners, process restarts,
bundle changes, expired/revoked trust, altered qualifications, invalid signatures
or changed approvals block release. A release's review expires at the original
approval deadline, at most fifteen minutes after requesting approval.

`provider-refresh` accepts fresh signed timestamps for the same evidence before
expiry. It preserves the release identity and cannot extend independent review,
change the serving process or revive a revoked release. Changed evidence needs
a new candidate and independent approvals. `provider-revoke-release` blocks
the release immediately; active tasks revalidate release identity before dispatch
and output retention. Lockdown changes invalidate prior authorization generations.

PUBLIC media suites use `aegis-media-qualification-v1`, `classification: PUBLIC`,
and `cases` with unique IDs, an `operation`, `prompt` and base64 `images`.
Understanding cases require `required_text` or `forbidden_text`. Generation/edit
cases check decoded output dimensions and latency; they do not evaluate visual
quality. PUBLIC embedding suites use `aegis-embedding-qualification-v1`, with
`query`, `documents` and `expected_index` per case. Ranking ties fail.

These are software checks and independently signed assertions. Live network
containment, real model quality, hardware attestation, and physical zeroization
remain outside the local test suite. Large bundle revalidation reads the declared
files; account for that I/O cost when choosing a deployment and lease lifetime.
