# AGOS ABI versioning and deprecation (Phase 6.9)

## Contract ids

- **`agos.v1`** — current stable contract (`AGOS_CONTRACT_ID` in **`agos-abi`**). Handshake **`schema_version`** stays **`1`** until a future handshake revision is documented in **`PLUGIN_CONTRACT.md`**.
- **`agos.v2`** — reserved string (`AGOS_CONTRACT_ID_V2`). Not in **`SUPPORTED_AGOS_CONTRACT_IDS`** until the kernel team completes migration tooling and dual-run testing.

## Kernel discovery

**`GET /api/v1`** and **`GET /health`** expose **`agos_abi`** including:

- **`contract_id`** — primary contract for this build (today **`agos.v1`**).
- **`supported_contract_ids`** — manifests must use one of these values in **`[plugin].agos_abi`** for install + tier admit.
- **`staged_contract_ids`** — optional early adopters / canary; empty until a staged rollout is announced.

## Deprecation policy (normative intent)

1. **Announce** a new contract in release notes + bump **`STAGED_AGOS_CONTRACT_IDS`** before it enters **`SUPPORTED_AGOS_CONTRACT_IDS`**.
2. **Overlap** — when **`agos.v2`** ships, **`supported_contract_ids`** lists **both** **`agos.v1`** and **`agos.v2`** for at least one **LTS** kernel minor; **`agos.v1`** remains valid until a published end-of-support date.
3. **Removal** — **`agos.v1`** drops from **`supported_contract_ids`** only after the EOL date; **`connectorctl plugin verify --require-kernel`** fails if a plugin still declares a removed id.
4. **Handshake** — if **`agos.v2`** requires handshake **`schema_version > 1`**, **`PLUGIN_CONTRACT.md`** is the source of truth; **`HANDSHAKE_SCHEMA_VERSION`** in **`agos-abi`** bumps with the doc.

## Author tooling

- Use **`agos_sdk::assert_manifest_matches_abi`** (checks **`SUPPORTED_AGOS_CONTRACT_IDS`**).
- CI should call **`connectorctl plugin verify`** against a kernel that matches production **`supported_contract_ids`**.
