---
id: sca-sast
kind: deterministic
command: bun {{HARNESS_DIR}}/tools/aidlc-sensor-sca-sast.ts
default_severity: advisory
description: SAST via downloaded Veracode CLI (fallback Pipeline Scan JAR) on packaged artifacts plus SCA via downloaded Veracode CLI on lockfile/manifest writes
category: security
matches: "**/*.{jar,war,ear,zip,class,json,lock,toml,txt,gradle,kts,yaml,yml,xml,csproj}"
input_schema:
  file_path: string
output_schema:
  pass: boolean
  findings_count: integer
timeout_seconds: 300
---

# sca-sast sensor

Runs two security checks in a single fire: **SAST** (static application security
testing) via the Veracode CLI (with Pipeline Scan JAR fallback) on packaged
artifacts, and **SCA** (software composition analysis) via the Veracode CLI on
dependency lockfile / manifest writes. The script downloads the latest Veracode
CLI and Pipeline Scan JAR into `aidlc/.aidlc-veracode/` (gitignored) and reuses
them when the cached version matches the latest release.

**Requires** `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET` environment
variables (both non-empty) before any download or scan. Missing credentials →
exit 127 with stderr `tool-unavailable`. Keys are never logged, never passed on
argv, and never written to JSON output.

## Tool download and cache

The sensor downloads tools on first use and caches them:

```
aidlc/.aidlc-veracode/
  cli/VERSION
  cli/<ver>/veracode[.exe]
  pipeline-scan/pipeline-scan.jar
  pipeline-scan/STAMP
```

Cache resolution walks up from `--file-path` until a directory `aidlc/` exists;
cache root is `aidlc/.aidlc-veracode/`. If no `aidlc/` is found, falls back to
`$TMPDIR/aidlc-veracode`. Override with `AIDLC_VERACODE_CACHE`.

On each fire that actually scans: HTTPS GET `LATEST_VERSION`. If the cached
version matches and the binary exists → reuse (zero download). Otherwise
downloads the CLI tarball and extracts it. The Pipeline Scan JAR is downloaded
from the official zip when the stamp is older than 24 hours.

**CLI tarball URL:** `https://tools.veracode.com/veracode-cli/veracode-cli_<VERSION>_<osArch>.tar.gz`
**Pipeline Scan zip:** `https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip`
**Latest version:** `https://tools.veracode.com/veracode-cli/LATEST_VERSION`

Supported platforms: linux x64/arm64, darwin x64/arm64, windows x64. Unsupported
platform → `tool-unavailable`.

## SAST half (packaged artifacts)

The SAST half fires only when a packaged artifact is available. Artifact
resolution checks, in order:

1. The `--file-path` argument itself, if its extension is `jar`, `war`, `ear`,
   `zip`, or `class` (case-insensitive).
2. `AIDLC_VERACODE_ARTIFACT` environment variable, if set and the file exists.
3. `VERACODE_SCAN_FILE` environment variable, if set and the file exists.

If no packaged artifact is found, SAST is skipped with note
`sast: no-packaged-artifact` — this is **not** a tool-unavailable condition and
does **not** fail the fire. The sensor does **not** scan raw source files and
does **not** auto-run `veracode package`.

**Primary tool:** cached CLI `static scan <artifact> --results-file <tmp> --fail-on-severity "Very High, High"`

**Fallback:** `java -jar pipeline-scan.jar --file <artifact> --fail_on_severity "Very High, High" --json_output_file <tmp>`

If neither the cached CLI nor the JAR (plus `java`) is available, the SAST half
is marked `tool-unavailable`.

Auth failures (HTTP 401) are treated as tool-unavailable; the sensor does not
invent credentials.

## SCA half (lockfiles / manifests)

The SCA half fires only when `--file-path` matches a known lockfile or manifest:
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`, `Cargo.lock`,
`requirements.txt`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `*.csproj`,
and `requirements-*.txt`.

The scan target is the nearest project root (walking up for `package.json`,
`go.mod`, `Cargo.toml`, or `pom.xml`), falling back to the directory of the
written file.

**Tool:** cached CLI `sca scan --target <projectRoot>` (alternate shape
`sca --target <dir>` if first fails). No `srcclr`.

If the cached CLI is unavailable, the SCA half is marked `tool-unavailable`.
Auth failures (HTTP 401) are treated as tool-unavailable.

## Fail bar

Only **Very High** and **High** severity findings set `pass: false`. Medium and
Low findings are recorded in the output but do not fail. Numeric severity values
5 and 4 are treated as Very High and High respectively. For SCA results that
provide only a CVSS score without an explicit severity label, the mapping is:
CVSS ≥ 9.0 → Very High, CVSS ≥ 7.0 → High, otherwise Medium.

## Failure mode

Emits `SENSOR_FAILED` and writes detail to
`aidlc/spaces/<active-space>/intents/<active-intent>/.aidlc-sensors/<stage-slug>/sca-sast-<fire-id>.md`,
where the space and intent come from the active cursors. The fire id is the
8-hex correlator from the `SENSOR_FIRED` row in the active record's
`audit/<host>-<clone-id>.md` shard. The detail contains the structured JSON
verdict (findings array, engine breakdown, notes).

## Tool-unavailable behavior

When the applicable half has no usable tool — SAST needs the downloaded CLI or
pipeline-scan.jar + java, SCA needs the downloaded CLI — the script exits 127
with stderr `tool-unavailable`. The dispatcher reclassifies this to
`SENSOR_PASSED` with `Note=tool-unavailable` — a quiet PASS rather than a
script-error. A partial miss (one tool present, the other absent) still runs the
available half and records the gap in `notes`. Missing a packaged artifact is
**not** tool-unavailable; it simply skips SAST. Missing credentials when a half
would run is also exit 127.
