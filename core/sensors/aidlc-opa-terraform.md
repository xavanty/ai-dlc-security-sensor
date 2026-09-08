---
id: opa-terraform
kind: deterministic
command: bun {{HARNESS_DIR}}/tools/aidlc-sensor-opa-terraform.ts
default_severity: advisory
description: Validates Terraform with conftest/OPA using project policies or bundled AWS defaults
category: security
matches: "**/*.{tf,tf.json}"
input_schema:
  file_path: string
output_schema:
  pass: boolean
  findings_count: integer
timeout_seconds: 60
---

# opa-terraform sensor

Validates Terraform configuration files (`*.tf` and `*.tf.json`) against OPA /
Conftest policies. The script walks up from the written file looking for a
project policy directory (first match wins): `.aidlc-opa/`,
`policy/terraform/`, or `policies/terraform/`. If none is found, a bundled
default Rego policy is written to a temp directory for this fire only.

## Bundled default denies

The embedded Rego package `terraform.aws` denies three common AWS mis-
configurations:

1. **S3 public ACL** — `acl = "public` or `block_public_acls = false`
2. **Unrestricted security-group ingress** — `0.0.0.0/0` in a CIDR block
3. **Explicit unencrypted storage** — `encrypted = false` on
   `aws_db_instance` or `aws_ebs_volume`

Only explicit `encrypted = false` is caught; the absence of an encryption
block is NOT a finding (avoids false positives on resources where encryption
defaults vary).

## Tool order

1. Probe `conftest --version`. If present, run `conftest test --parser hcl`
   (or `--parser json` for `.tf.json`) against the file.
2. Else probe `opa version`. If present, wrap the file as
   `{"raw": "<contents>"}` and evaluate `data.terraform.aws.deny`.
3. Else exit 127 (`opa-unavailable`).

## Failure mode

Emits `SENSOR_FAILED` and writes detail to
`aidlc/spaces/<active-space>/intents/<active-intent>/.aidlc-sensors/<stage-slug>/opa-terraform-<fire-id>.md`,
where the space and intent come from the active cursors. The fire id is the
8-hex correlator from the `SENSOR_FIRED` row in the active record's
`audit/<host>-<clone-id>.md` shard. The detail contains the structured JSON
verdict (findings array, engine, policy source, notes).
