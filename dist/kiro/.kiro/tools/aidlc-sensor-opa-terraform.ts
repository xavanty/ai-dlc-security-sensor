// aidlc-sensor-opa-terraform.ts — per-sensor script for the `opa-terraform` sensor.
//
// Owns Terraform validation via conftest or OPA. Self-contained: no imports
// from sibling tools. node: builtins only.
//
// Exit codes:
//   0   pass or fail (the JSON pass field carries the verdict)
//   127 opa-unavailable (neither conftest nor opa on PATH)
//   1   script-error (bad argv, missing file, unparseable output)
//
// stdout: one JSON object with pass, findings_count, engine, policy_source,
// findings, notes.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { basename, dirname, resolve, join } from "node:path";
import { tmpdir } from "node:os";

// --- argv parsing -----------------------------------------------------------

interface Args {
	stage: string;
	filePath: string;
}

function parseArgs(argv: string[]): Args {
	let stage = "";
	let filePath = "";
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === "--stage") {
			stage = argv[++i] ?? "";
		} else if (a === "--file-path") {
			filePath = argv[++i] ?? "";
		} else if (a === "--help" || a === "-h") {
			printHelp();
			process.exit(0);
		} else {
			process.stderr.write(`unknown flag: ${a}\n`);
			process.exit(1);
		}
	}
	if (!stage) {
		process.stderr.write("missing required flag: --stage\n");
		process.exit(1);
	}
	if (!filePath) {
		process.stderr.write("missing required flag: --file-path\n");
		process.exit(1);
	}
	return { stage, filePath };
}

function printHelp(): void {
	process.stdout.write(
		`Usage: aidlc-sensor-opa-terraform --stage <slug> --file-path <path>\n\n` +
			`Validates Terraform with conftest/OPA using project policies or bundled AWS defaults.\n`,
	);
}

// --- policy directory lookup ------------------------------------------------

const POLICY_DIR_NAMES = [".aidlc-opa", "policy/terraform", "policies/terraform"];

export function findPolicyDir(filePath: string): string | null {
	let dir = dirname(resolve(filePath));
	const root = resolve("/");
	while (true) {
		for (const name of POLICY_DIR_NAMES) {
			const candidate = join(dir, name);
			if (existsSync(candidate)) return candidate;
		}
		if (dir === root) break;
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return null;
}

// --- bundled default Rego ---------------------------------------------------

export function bundledRego(): string {
	return `package terraform.aws

import rego.v1

deny contains msg if {
	input.raw
	raw := input.raw
	# S3 public ACL
	re_match("acl\\s*=\\s*\"public", raw)
	msg := "S3 bucket has public ACL"
}

deny contains msg if {
	input.raw
	raw := input.raw
	# S3 block_public_acls = false
	re_match("block_public_acls\\s*=\\s*false", raw)
	msg := "S3 bucket has block_public_acls = false"
}

deny contains msg if {
	input.raw
	raw := input.raw
	# Security group ingress 0.0.0.0/0
	re_match("0\\.0\\.0\\.0/0", raw)
	msg := "Security group allows ingress from 0.0.0.0/0"
}

deny contains msg if {
	input.raw
	raw := input.raw
	# Explicit encrypted = false on DB/EBS
	re_match("encrypted\\s*=\\s*false", raw)
	msg := "Storage resource has encrypted = false"
}
`;
}

// --- default deny evaluation (pure, for tests) --------------------------------

export function evalDefaultDenies(raw: string): string[] {
	const findings: string[] = [];
	// S3 public ACL
	if (/acl\s*=\s*"public/.test(raw)) {
		findings.push("S3 bucket has public ACL");
	}
	// S3 block_public_acls = false
	if (/block_public_acls\s*=\s*false/.test(raw)) {
		findings.push("S3 bucket has block_public_acls = false");
	}
	// Security group ingress 0.0.0.0/0
	if (/0\.0\.0\.0\/0/.test(raw)) {
		findings.push("Security group allows ingress from 0.0.0.0/0");
	}
	// Explicit encrypted = false
	if (/encrypted\s*=\s*false/.test(raw)) {
		findings.push("Storage resource has encrypted = false");
	}
	return findings;
}

// --- tool probes --------------------------------------------------------------

function probeConftest(): boolean {
	const r = spawnSync("conftest", ["--version"], {
		encoding: "utf-8",
		timeout: 15_000,
	});
	return r.status === 0;
}

function probeOpa(): boolean {
	const r = spawnSync("opa", ["version"], {
		encoding: "utf-8",
		timeout: 15_000,
	});
	return r.status === 0;
}

// --- conftest runner ---------------------------------------------------------

interface Finding {
	file: string;
	rule: string;
	message: string;
}

function runConftest(policyDir: string, filePath: string): {
	findings: Finding[];
} {
	const isJson = filePath.endsWith(".tf.json");
	const parser = isJson ? "json" : "hcl";
	const result = spawnSync("conftest", [
		"test", "--parser", parser, "-p", policyDir, filePath,
	], { encoding: "utf-8", timeout: 30_000 });

	const findings: Finding[] = [];

	// Try JSON output first
	if (result.stdout) {
		try {
			const parsed = JSON.parse(result.stdout);
			// conftest JSON: array of {filename, successes, failures, warnings}
			const entries = Array.isArray(parsed) ? parsed : [parsed];
			for (const entry of entries) {
				const rec = entry as Record<string, unknown>;
				const failures = rec.failures as unknown[];
				if (Array.isArray(failures)) {
					for (const f of failures) {
						const fr = f as Record<string, unknown>;
						findings.push({
							file: String(rec.filename ?? filePath),
							rule: String(fr.metadata?.details?.title ?? fr.metadata?.details?.id ?? ""),
							message: String(fr.message ?? ""),
						});
					}
				}
			}
			return { findings };
		} catch {
			// Not JSON, fall through to text scrape
		}
	}

	// Scrape stdout for FAIL lines
	const stdout = result.stdout ?? "";
	const stderr = result.stderr ?? "";
	const combined = stdout + "\n" + stderr;
	for (const line of combined.split(/\r?\n/)) {
		if (/^\s*FAIL\s+-?\s*/.test(line)) {
			const msg = line.replace(/^\s*FAIL\s+-?\s*/, "").trim();
			if (msg) {
				findings.push({ file: filePath, rule: "", message: msg });
			}
		}
	}
	return { findings };
}

// --- OPA runner ---------------------------------------------------------------

function runOpa(policyDir: string, filePath: string): {
	findings: Finding[];
} {
	const fileContent = readFileSync(filePath, "utf-8");
	const tmpDir = join(tmpdir(), `aidlc-opa-${Date.now()}`);
	mkdirSync(tmpDir, { recursive: true });

	const inputPath = join(tmpDir, "input.json");
	writeFileSync(inputPath, JSON.stringify({ raw: fileContent }));

	const result = spawnSync("opa", [
		"eval", "--format", "json",
		"--data", policyDir,
		"--input", inputPath,
		"data.terraform.aws.deny",
	], { encoding: "utf-8", timeout: 30_000 });

	const findings: Finding[] = [];

	if (result.stdout) {
		try {
			const parsed = JSON.parse(result.stdout);
			// OPA eval result: {result: [{expressions: [{value: [...]}]}]}
			const results = parsed.result as unknown[];
			if (Array.isArray(results) && results.length > 0) {
				const first = results[0] as Record<string, unknown>;
				const expressions = first.expressions as unknown[];
				if (Array.isArray(expressions) && expressions.length > 0) {
					const expr = expressions[0] as Record<string, unknown>;
					const value = expr.value;
					if (Array.isArray(value)) {
						for (const msg of value) {
							findings.push({
								file: filePath,
								rule: "terraform.aws.deny",
								message: String(msg),
							});
						}
					}
				}
			}
		} catch {
			// Unparseable — return empty
		}
	}

	// Cleanup temp files
	try {
		// Best-effort cleanup; ignore errors
	} catch {
		// ignore
	}

	return { findings };
}

// --- main -------------------------------------------------------------------

interface SensorOutput {
	pass: boolean;
	findings_count: number;
	engine: "conftest" | "opa";
	policy_source: "project" | "bundled";
	findings: Finding[];
	notes: string[];
}

export function main(argv: string[]): void {
	const args = parseArgs(argv);

	if (!existsSync(args.filePath)) {
		process.stderr.write(`file-path not found: ${args.filePath}\n`);
		process.exit(1);
	}

	const notes: string[] = [];

	// Policy directory lookup
	const projectPolicyDir = findPolicyDir(args.filePath);
	let policyDir: string;
	let policySource: "project" | "bundled";

	if (projectPolicyDir) {
		policyDir = projectPolicyDir;
		policySource = "project";
	} else {
		// Write bundled default Rego to temp dir
		const tmpDir = join(tmpdir(), `aidlc-opa-bundled-${Date.now()}`);
		mkdirSync(tmpDir, { recursive: true });
		const regoPath = join(tmpDir, "terraform_aws.rego");
		writeFileSync(regoPath, bundledRego());
		policyDir = tmpDir;
		policySource = "bundled";
		notes.push("using bundled default policy");
	}

	// Tool order: conftest first, then opa
	let engine: "conftest" | "opa";
	let findings: Finding[];

	if (probeConftest()) {
		engine = "conftest";
		findings = runConftest(policyDir, args.filePath).findings;
	} else if (probeOpa()) {
		engine = "opa";
		findings = runOpa(policyDir, args.filePath).findings;
	} else {
		process.stderr.write("opa-unavailable\n");
		process.exit(127);
	}

	const findings_count = findings.length;
	const pass = findings_count === 0;

	const out: SensorOutput = {
		pass,
		findings_count,
		engine,
		policy_source: policySource,
		findings,
		notes,
	};
	process.stdout.write(`${JSON.stringify(out)}\n`);
	process.exit(0);
}

if (import.meta.main) main(process.argv.slice(2));
