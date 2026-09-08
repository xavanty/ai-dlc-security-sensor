// covers: tool:aidlc-sensor-sca-sast, tool:aidlc-sensor-opa-terraform
//
// t330 — unit tests for the sca-sast and opa-terraform sensors.
// Tests path classifiers, JSON parsers, severity logic, download/cache helpers,
// and default Rego denies — no Veracode/java/opa/conftest required, no network.

import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import {
  isPackagedArtifact,
  isLockfilePath,
  severityIsFailBar,
  parsePipelineScanJson,
  parseVeracodeScaJson,
  cliOsArch,
  hasVeracodeCreds,
  parseLatestVersion,
  cacheCliFresh,
  isAllowedVeracodeHost,
} from "../../core/tools/aidlc-sensor-sca-sast.ts";
import {
  findPolicyDir,
  bundledRego,
  evalDefaultDenies,
} from "../../core/tools/aidlc-sensor-opa-terraform.ts";

// ===========================================================================
// sca-sast: path classification
// ===========================================================================

describe("t330 sca-sast path classification", () => {
  test("isPackagedArtifact returns true for packaged extensions", () => {
    expect(isPackagedArtifact("app.jar")).toBe(true);
    expect(isPackagedArtifact("app.war")).toBe(true);
    expect(isPackagedArtifact("app.ear")).toBe(true);
    expect(isPackagedArtifact("archive.zip")).toBe(true);
    expect(isPackagedArtifact("Foo.class")).toBe(true);
    // case-insensitive
    expect(isPackagedArtifact("app.JAR")).toBe(true);
    expect(isPackagedArtifact("app.War")).toBe(true);
  });

  test("isPackagedArtifact returns false for non-packaged extensions", () => {
    expect(isPackagedArtifact("src/app.ts")).toBe(false);
    expect(isPackagedArtifact("package-lock.json")).toBe(false);
    expect(isPackagedArtifact("yarn.lock")).toBe(false);
    expect(isPackagedArtifact("README.md")).toBe(false);
    expect(isPackagedArtifact("pom.xml")).toBe(false);
  });

  test("isLockfilePath returns true for known lockfiles", () => {
    expect(isLockfilePath("package-lock.json")).toBe(true);
    expect(isLockfilePath("yarn.lock")).toBe(true);
    expect(isLockfilePath("pnpm-lock.yaml")).toBe(true);
    expect(isLockfilePath("go.sum")).toBe(true);
    expect(isLockfilePath("Cargo.lock")).toBe(true);
    expect(isLockfilePath("requirements.txt")).toBe(true);
    expect(isLockfilePath("pom.xml")).toBe(true);
    expect(isLockfilePath("build.gradle")).toBe(true);
    expect(isLockfilePath("build.gradle.kts")).toBe(true);
    expect(isLockfilePath("MyProject.csproj")).toBe(true);
    expect(isLockfilePath("requirements-dev.txt")).toBe(true);
    expect(isLockfilePath("requirements-test.txt")).toBe(true);
  });

  test("isLockfilePath returns false for non-lockfile paths", () => {
    expect(isLockfilePath("src/app.ts")).toBe(false);
    expect(isLockfilePath("README.md")).toBe(false);
    expect(isLockfilePath("requirements.txt.bak")).toBe(false);
  });
});

// ===========================================================================
// sca-sast: severityIsFailBar
// ===========================================================================

describe("t330 severityIsFailBar", () => {
  test("Very High and High return true", () => {
    expect(severityIsFailBar("Very High")).toBe(true);
    expect(severityIsFailBar("very high")).toBe(true);
    expect(severityIsFailBar("HIGH")).toBe(true);
    expect(severityIsFailBar("high")).toBe(true);
  });

  test("numeric 5 and 4 return true", () => {
    expect(severityIsFailBar(5)).toBe(true);
    expect(severityIsFailBar(4)).toBe(true);
    expect(severityIsFailBar("5")).toBe(true);
    expect(severityIsFailBar("4")).toBe(true);
  });

  test("Medium, Low, 3, 2, empty string return false", () => {
    expect(severityIsFailBar("Medium")).toBe(false);
    expect(severityIsFailBar("LOW")).toBe(false);
    expect(severityIsFailBar(3)).toBe(false);
    expect(severityIsFailBar(2)).toBe(false);
    expect(severityIsFailBar("")).toBe(false);
  });

  test("CRITICAL returns false (not in fail bar)", () => {
    expect(severityIsFailBar("CRITICAL")).toBe(false);
    expect(severityIsFailBar("critical")).toBe(false);
  });
});

// ===========================================================================
// sca-sast: parsePipelineScanJson
// ===========================================================================

describe("t330 parsePipelineScanJson", () => {
  test("numeric severity 5 counts as fail bar", () => {
    const raw = JSON.stringify({
      findings: [
        {
          title: "SQL Injection",
          severity: 5,
          cwe_id: 89,
          files: { source_file: { file: "Foo.java", line: 10 } },
        },
      ],
    });
    const { failBarCount, findings } = parsePipelineScanJson(raw, "Foo.jar");
    expect(failBarCount).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].engine).toBe("sast");
    expect(findings[0].file).toBe("Foo.java");
    expect(findings[0].line).toBe(10);
    expect(findings[0].rule).toBe("CWE-89");
    expect(findings[0].severity).toBe("5");
  });

  test("string High counts as fail bar", () => {
    const raw = JSON.stringify({
      findings: [
        {
          title: "XSS vulnerability",
          severity: "High",
          cwe_id: 79,
          files: { source_file: { file: "Bar.java", line: 22 } },
        },
      ],
    });
    const { failBarCount, findings } = parsePipelineScanJson(raw, "Bar.war");
    expect(failBarCount).toBe(1);
    expect(findings[0].severity).toBe("High");
  });

  test("Medium does not count as fail bar", () => {
    const raw = JSON.stringify({
      findings: [
        {
          title: "Info disclosure",
          severity: "Medium",
          cwe_id: 200,
          files: { source_file: { file: "Baz.java", line: 5 } },
        },
      ],
    });
    const { failBarCount, findings } = parsePipelineScanJson(raw, "Baz.jar");
    expect(failBarCount).toBe(0);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("Medium");
  });

  test("mixed severities: only Very High/High count", () => {
    const raw = JSON.stringify({
      findings: [
        { title: "RCE", severity: "Very High", cwe_id: 78, files: { source_file: { file: "A.java", line: 1 } } },
        { title: "SQLi", severity: "High", cwe_id: 89, files: { source_file: { file: "B.java", line: 2 } } },
        { title: "Info", severity: "Low", cwe_id: 200, files: { source_file: { file: "C.java", line: 3 } } },
        { title: "XSS", severity: 5, cwe_id: 79, files: { source_file: { file: "D.java", line: 4 } } },
        { title: "Leak", severity: 3, cwe_id: 532, files: { source_file: { file: "E.java", line: 5 } } },
      ],
    });
    const { failBarCount, findings } = parsePipelineScanJson(raw, "Mix.jar");
    expect(failBarCount).toBe(3); // Very High, High, 5
    expect(findings).toHaveLength(5);
  });

  test("empty findings array", () => {
    const raw = JSON.stringify({ findings: [] });
    const { failBarCount, findings } = parsePipelineScanJson(raw, "Clean.jar");
    expect(failBarCount).toBe(0);
    expect(findings).toHaveLength(0);
  });

  test("unparseable JSON returns empty without throwing", () => {
    const { failBarCount, findings } = parsePipelineScanJson("not json", "Foo.jar");
    expect(failBarCount).toBe(0);
    expect(findings).toHaveLength(0);
  });
});

// ===========================================================================
// sca-sast: parseVeracodeScaJson
// ===========================================================================

describe("t330 parseVeracodeScaJson", () => {
  test("High + Medium vulns: only High counts", () => {
    const raw = JSON.stringify({
      records: [
        {
          library: "lodash",
          vulnerabilities: [
            { id: "CVE-2024-1234", severity: "High", summary: "Prototype pollution" },
            { id: "CVE-2024-5678", severity: "Medium", summary: "ReDoS" },
          ],
        },
      ],
    });
    const { failBarCount, findings } = parseVeracodeScaJson(raw);
    expect(failBarCount).toBe(1);
    expect(findings).toHaveLength(2);
    expect(findings[0].engine).toBe("sca");
    expect(findings[0].file).toBe("lodash");
    expect(findings[0].severity).toBe("High");
  });

  test("CVSS-only mapping: >=9 Very High, >=7 High", () => {
    const raw = JSON.stringify({
      records: [
        {
          library: "express",
          vulnerabilities: [
            { id: "CVE-2024-0001", cvss: 9.8, summary: "RCE" },
            { id: "CVE-2024-0002", cvss: 7.5, summary: "DoS" },
            { id: "CVE-2024-0003", cvss: 4.3, summary: "Info leak" },
          ],
        },
      ],
    });
    const { failBarCount, findings } = parseVeracodeScaJson(raw);
    expect(failBarCount).toBe(2); // 9.8 → Very High, 7.5 → High
    expect(findings[0].severity).toBe("Very High");
    expect(findings[1].severity).toBe("High");
    expect(findings[2].severity).toBe("Medium");
  });

  test("unparseable JSON throws", () => {
    expect(() => parseVeracodeScaJson("not json")).toThrow("veracode-sca-bad-output");
  });

  test("missing records array throws", () => {
    expect(() => parseVeracodeScaJson(JSON.stringify({}))).toThrow("veracode-sca-bad-output");
  });
});

// ===========================================================================
// opa-terraform: policy directory lookup
// ===========================================================================

describe("t330 opa-terraform findPolicyDir", () => {
  test("returns null when no policy dir exists", () => {
    // Use a temp path that won't have policy dirs
    const result = findPolicyDir("/tmp/aidlc-test-no-policy/test.tf");
    expect(result).toBeNull();
  });
});

// ===========================================================================
// opa-terraform: bundled Rego + default denies
// ===========================================================================

describe("t330 opa-terraform bundledRego", () => {
  test("bundledRego returns non-empty string with package declaration", () => {
    const rego = bundledRego();
    expect(rego.length).toBeGreaterThan(0);
    expect(rego).toContain("package terraform.aws");
    expect(rego).toContain("deny contains msg if");
  });
});

describe("t330 opa-terraform evalDefaultDenies", () => {
  test("detects public S3 ACL", () => {
    const tf = `
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.includes("public ACL") || f.includes("block_public_acls"))).toBe(true);
  });

  test("detects block_public_acls = false", () => {
    const tf = `
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket = aws_s3_bucket.my.id
  block_public_acls = false
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings.some((f) => f.includes("block_public_acls"))).toBe(true);
  });

  test("detects 0.0.0.0/0 in security group", () => {
    const tf = `
resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
  }
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings.some((f) => f.includes("0.0.0.0/0"))).toBe(true);
  });

  test("detects encrypted = false", () => {
    const tf = `
resource "aws_db_instance" "unencrypted" {
  allocated_storage = 20
  encrypted = false
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings.some((f) => f.includes("encrypted = false"))).toBe(true);
  });

  test("clean terraform produces no findings", () => {
    const tf = `
resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
}

resource "aws_db_instance" "encrypted" {
  allocated_storage = 20
  encrypted = true
}

resource "aws_security_group" "restricted" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
    from_port   = 443
    to_port     = 443
  }
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings).toHaveLength(0);
  });

  test("absence of encryption block is NOT a finding", () => {
    const tf = `
resource "aws_db_instance" "no_encryption_field" {
  allocated_storage = 20
  engine = "mysql"
}
`;
    const findings = evalDefaultDenies(tf);
    expect(findings).toHaveLength(0);
  });
});

// ===========================================================================
// sca-sast: cliOsArch table
// ===========================================================================

describe("t330 cliOsArch", () => {
  test("linux x64 → linux_x64", () => {
    expect(cliOsArch("linux", "x64")).toBe("linux_x64");
  });
  test("linux arm64 → linux_arm64", () => {
    expect(cliOsArch("linux", "arm64")).toBe("linux_arm64");
  });
  test("darwin x64 → macosx_x64", () => {
    expect(cliOsArch("darwin", "x64")).toBe("macosx_x64");
  });
  test("darwin arm64 → macosx_arm64", () => {
    expect(cliOsArch("darwin", "arm64")).toBe("macosx_arm64");
  });
  test("win32 x64 → windows_x64", () => {
    expect(cliOsArch("win32", "x64")).toBe("windows_x64");
  });
  test("win32 ia32 → windows_x64", () => {
    expect(cliOsArch("win32", "ia32")).toBe("windows_x64");
  });
  test("unsupported platforms → null", () => {
    expect(cliOsArch("linux", "arm")).toBeNull();
    expect(cliOsArch("freebsd", "x64")).toBeNull();
    expect(cliOsArch("win32", "arm64")).toBeNull();
    expect(cliOsArch("darwin", "arm")).toBeNull();
  });
});

// ===========================================================================
// sca-sast: hasVeracodeCreds
// ===========================================================================

describe("t330 hasVeracodeCreds", () => {
  const ORIG_ID = process.env.VERACODE_API_KEY_ID;
  const ORIG_SECRET = process.env.VERACODE_API_KEY_SECRET;

  afterAll(() => {
    process.env.VERACODE_API_KEY_ID = ORIG_ID ?? "";
    process.env.VERACODE_API_KEY_SECRET = ORIG_SECRET ?? "";
    if (ORIG_ID === undefined) delete process.env.VERACODE_API_KEY_ID;
    if (ORIG_SECRET === undefined) delete process.env.VERACODE_API_KEY_SECRET;
  });

  test("both set → true", () => {
    process.env.VERACODE_API_KEY_ID = "test-id";
    process.env.VERACODE_API_KEY_SECRET = "test-secret";
    expect(hasVeracodeCreds()).toBe(true);
  });

  test("missing id → false", () => {
    delete process.env.VERACODE_API_KEY_ID;
    process.env.VERACODE_API_KEY_SECRET = "test-secret";
    expect(hasVeracodeCreds()).toBe(false);
  });

  test("missing secret → false", () => {
    process.env.VERACODE_API_KEY_ID = "test-id";
    delete process.env.VERACODE_API_KEY_SECRET;
    expect(hasVeracodeCreds()).toBe(false);
  });

  test("both missing → false", () => {
    delete process.env.VERACODE_API_KEY_ID;
    delete process.env.VERACODE_API_KEY_SECRET;
    expect(hasVeracodeCreds()).toBe(false);
  });

  test("empty string id → false", () => {
    process.env.VERACODE_API_KEY_ID = "";
    process.env.VERACODE_API_KEY_SECRET = "test-secret";
    expect(hasVeracodeCreds()).toBe(false);
  });

  test("empty string secret → false", () => {
    process.env.VERACODE_API_KEY_ID = "test-id";
    process.env.VERACODE_API_KEY_SECRET = "";
    expect(hasVeracodeCreds()).toBe(false);
  });
});

// ===========================================================================
// sca-sast: parseLatestVersion
// ===========================================================================

describe("t330 parseLatestVersion", () => {
  test("trims whitespace", () => {
    expect(parseLatestVersion("  1.2.3  \n")).toBe("1.2.3");
  });
  test("rejects empty string", () => {
    expect(parseLatestVersion("")).toBe("");
    expect(parseLatestVersion("   ")).toBe("");
  });
  test("rejects path-like input", () => {
    expect(parseLatestVersion("/some/path")).toBe("");
    expect(parseLatestVersion("C:\\Windows\\path")).toBe("");
  });
  test("rejects URL-like input", () => {
    expect(parseLatestVersion("https://example.com/1.2.3")).toBe("");
  });
  test("accepts plain version", () => {
    expect(parseLatestVersion("2.0.0")).toBe("2.0.0");
    expect(parseLatestVersion("1.0.0-rc1")).toBe("1.0.0-rc1");
  });
});

// ===========================================================================
// sca-sast: cacheCliFresh
// ===========================================================================

describe("t330 cacheCliFresh", () => {
  test("matching version + binary exists → true", () => {
    expect(cacheCliFresh("1.2.3", "1.2.3", true)).toBe(true);
  });
  test("matching version + no binary → false", () => {
    expect(cacheCliFresh("1.2.3", "1.2.3", false)).toBe(false);
  });
  test("mismatched version + binary exists → false", () => {
    expect(cacheCliFresh("1.2.2", "1.2.3", true)).toBe(false);
  });
  test("null cached version → false", () => {
    expect(cacheCliFresh(null, "1.2.3", true)).toBe(false);
  });
  test("null cached version + no binary → false", () => {
    expect(cacheCliFresh(null, "1.2.3", false)).toBe(false);
  });
});

// ===========================================================================
// sca-sast: isAllowedVeracodeHost (redirect guard)
// ===========================================================================

describe("t330 isAllowedVeracodeHost", () => {
  test("tools.veracode.com → true", () => {
    expect(isAllowedVeracodeHost("tools.veracode.com")).toBe(true);
  });
  test("downloads.veracode.com → true", () => {
    expect(isAllowedVeracodeHost("downloads.veracode.com")).toBe(true);
  });
  test("evil.com → false", () => {
    expect(isAllowedVeracodeHost("evil.com")).toBe(false);
  });
  test("tools.veracode.com.evil.com → false", () => {
    expect(isAllowedVeracodeHost("tools.veracode.com.evil.com")).toBe(false);
  });
  test("empty string → false", () => {
    expect(isAllowedVeracodeHost("")).toBe(false);
  });
  test("subdomain of allowed host → false", () => {
    expect(isAllowedVeracodeHost("fake.tools.veracode.com")).toBe(false);
  });
});
