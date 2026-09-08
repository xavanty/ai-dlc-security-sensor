// aidlc-sensor-sca-sast.ts — per-sensor script for the `sca-sast` sensor.
//
// Owns SAST (Veracode CLI / Pipeline Scan JAR) + SCA (Veracode CLI) in one fire.
// Downloads latest Veracode CLI + pipeline-scan.jar into aidlc/.aidlc-veracode/
// (gitignored). Requires VERACODE_API_KEY_ID + VERACODE_API_KEY_SECRET env vars.
// Self-contained: no imports from sibling tools. node: builtins only.
//
// Exit codes:
//   0   pass or fail (the JSON pass field carries the verdict)
//   127 tool-unavailable (no usable tool for the work this fire needed)
//   1   script-error (bad argv, missing file, unparseable tool output)
//
// stdout: one JSON object with pass, findings_count, sast, sca, findings, notes.

import { spawnSync } from "node:child_process";
import {
	existsSync,
	readFileSync,
	unlinkSync,
	mkdirSync,
	writeFileSync,
	chmodSync,
	readdirSync,
	copyFileSync,
	rmSync,
} from "node:fs";
import { basename, dirname, extname, resolve, join } from "node:path";
import { tmpdir, platform, arch } from "node:os";
import { get } from "node:https";

// --- URL constants (exported for tests) -------------------------------------

export const CLI_HOST = "tools.veracode.com";
export const PIPELINE_HOST = "downloads.veracode.com";
export const CLI_DOWNLOAD = `https://${CLI_HOST}/veracode-cli`;
export const PIPELINE_ZIP_URL = `https://${PIPELINE_HOST}/securityscan/pipeline-scan-LATEST.zip`;
export const LATEST_VERSION_URL = `${CLI_DOWNLOAD}/LATEST_VERSION`;

// --- redirect guard (exported for tests) ------------------------------------

const ALLOWED_HOSTS = new Set([CLI_HOST, PIPELINE_HOST]);

export function isAllowedVeracodeHost(hostname: string): boolean {
	return ALLOWED_HOSTS.has(hostname);
}

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
		`Usage: aidlc-sensor-sca-sast --stage <slug> --file-path <path>\n\n` +
			`Runs Veracode CLI (SAST) on packaged artifacts and Veracode CLI (SCA) on lockfile/manifest writes.\n` +
			`Downloads latest tools into aidlc/.aidlc-veracode/ (gitignored).\n` +
			`Requires VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET environment variables.\n`,
	);
}

// --- path classification ----------------------------------------------------

const PACKAGED_EXTS = new Set(["jar", "war", "ear", "zip", "class"]);

const LOCKFILE_BASENAMES = new Set([
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
	"Cargo.lock", "requirements.txt", "pom.xml", "build.gradle",
	"build.gradle.kts",
]);

export function isPackagedArtifact(filePath: string): boolean {
	const ext = extname(filePath).replace(/^\./, "").toLowerCase();
	return PACKAGED_EXTS.has(ext);
}

export function isLockfilePath(filePath: string): boolean {
	const bn = basename(filePath);
	if (LOCKFILE_BASENAMES.has(bn)) return true;
	if (bn.endsWith(".csproj")) return true;
	if (/^requirements-.*\.txt$/.test(bn)) return true;
	return false;
}

// --- artifact resolution for SAST -------------------------------------------

export function resolveSastArtifact(filePath: string): string | null {
	// 1. --file-path ext in jar,war,ear,zip,class (case-insensitive)
	if (isPackagedArtifact(filePath)) return resolve(filePath);
	// 2. env AIDLC_VERACODE_ARTIFACT if set and exists
	const envArtifact = process.env.AIDLC_VERACODE_ARTIFACT;
	if (envArtifact && existsSync(envArtifact)) return resolve(envArtifact);
	// 3. env VERACODE_SCAN_FILE if set and exists
	const envScanFile = process.env.VERACODE_SCAN_FILE;
	if (envScanFile && existsSync(envScanFile)) return resolve(envScanFile);
	// 4. no packaged artifact
	return null;
}

// --- severity helpers -------------------------------------------------------

// Fail bar: Very High + High only. Medium/Low recorded, pass=true.
// Accepts string ("Very High", "High", "Medium", "Low") or numeric (5,4,3,2).
export function severityIsFailBar(severity: string | number): boolean {
	const s = typeof severity === "number" ? String(severity) : severity;
	const upper = s.trim().toUpperCase();
	if (upper === "VERY HIGH" || upper === "HIGH") return true;
	if (s === "5" || s === "4") return true;
	return false;
}

// --- credentials check (exported for tests) ---------------------------------

export function hasVeracodeCreds(): boolean {
	const id = process.env.VERACODE_API_KEY_ID;
	const secret = process.env.VERACODE_API_KEY_SECRET;
	return typeof id === "string" && id.length > 0 &&
		typeof secret === "string" && secret.length > 0;
}

// --- os/arch mapper (exported for tests) ------------------------------------

export function cliOsArch(plat: string, arc: string): string | null {
	if (plat === "linux" && arc === "x64") return "linux_x64";
	if (plat === "linux" && arc === "arm64") return "linux_arm64";
	if (plat === "darwin" && arc === "x64") return "macosx_x64";
	if (plat === "darwin" && arc === "arm64") return "macosx_arm64";
	if (plat === "win32" && (arc === "x64" || arc === "ia32")) return "windows_x64";
	return null;
}

// --- parse latest version (exported for tests) ------------------------------

export function parseLatestVersion(raw: string): string {
	const trimmed = raw.trim();
	if (!trimmed) return "";
	// Reject if it looks like a path or URL
	if (trimmed.includes("/") || trimmed.includes("\\")) return "";
	return trimmed;
}

// --- cache helpers (exported for tests) -------------------------------------

export function cacheCliFresh(
	cachedVersion: string | null,
	latest: string,
	binaryExists: boolean,
): boolean {
	return cachedVersion === latest && binaryExists;
}

// --- cache directory resolution ---------------------------------------------

function resolveCacheDir(filePath: string): string {
	// Override
	const override = process.env.AIDLC_VERACODE_CACHE;
	if (override) return override;

	// Walk up from filePath until directory "aidlc/" exists
	let dir = dirname(resolve(filePath));
	while (true) {
		if (existsSync(join(dir, "aidlc"))) {
			return join(dir, "aidlc", ".aidlc-veracode");
		}
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}

	// Fallback: system temp
	return join(tmpdir(), "aidlc-veracode");
}

function cliBinaryName(): string {
	return platform() === "win32" ? "veracode.exe" : "veracode";
}

// --- HTTPS GET helper (node:https, follow redirects) ------------------------

function httpsGet(url: string, timeoutMs: number): Promise<string> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("https-get-timeout")), timeoutMs);
		const follow = (u: string) => {
			get(u, { timeout: timeoutMs }, (res) => {
				if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
					const loc = res.headers.location;
					if (loc) {
						const next = loc.startsWith("http") ? loc : new URL(loc, u).href;
						const parsed = new URL(next);
						if (!isAllowedVeracodeHost(parsed.hostname)) {
							clearTimeout(timer);
							reject(new Error(`redirect-rejected-host:${parsed.hostname}`));
							return;
						}
						follow(next);
						return;
					}
				}
				let data = "";
				res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
				res.on("end", () => {
					clearTimeout(timer);
					if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
						resolve(data);
					} else {
						reject(new Error(`http-status-${res.statusCode}`));
					}
				});
				res.on("error", (e) => { clearTimeout(timer); reject(e); });
			}).on("error", (e) => { clearTimeout(timer); reject(e); });
		};
		follow(url);
	});
}

function httpsGetBinary(url: string, timeoutMs: number): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("https-get-timeout")), timeoutMs);
		const follow = (u: string) => {
			get(u, { timeout: timeoutMs }, (res) => {
				if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
					const loc = res.headers.location;
					if (loc) {
						const next = loc.startsWith("http") ? loc : new URL(loc, u).href;
						const parsed = new URL(next);
						if (!isAllowedVeracodeHost(parsed.hostname)) {
							clearTimeout(timer);
							reject(new Error(`redirect-rejected-host:${parsed.hostname}`));
							return;
						}
						follow(next);
						return;
					}
				}
				const chunks: Buffer[] = [];
				res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
				res.on("end", () => {
					clearTimeout(timer);
					if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
						resolve(Buffer.concat(chunks));
					} else {
						reject(new Error(`http-status-${res.statusCode}`));
					}
				});
				res.on("error", (e) => { clearTimeout(timer); reject(e); });
			}).on("error", (e) => { clearTimeout(timer); reject(e); });
		};
		follow(url);
	});
}

// --- download / extract logic -----------------------------------------------

function ensureDir(p: string): void {
	if (!existsSync(p)) mkdirSync(p, { recursive: true });
}

function readCachedVersion(cacheDir: string): string | null {
	const verFile = join(cacheDir, "cli", "VERSION");
	if (existsSync(verFile)) {
		try {
			return readFileSync(verFile, "utf-8").trim();
		} catch { /* ignore */ }
	}
	return null;
}

function binaryExistsAt(cacheDir: string, ver: string): boolean {
	const binPath = join(cacheDir, "cli", ver, cliBinaryName());
	return existsSync(binPath);
}

function extractTarball(buf: Buffer, destDir: string): boolean {
	// Write to temp, extract with tar
	const tmpTar = join(tmpdir(), `aidlc-veracode-cli-${Date.now()}.tar.gz`);
	try {
		writeFileSync(tmpTar, buf);
		// tar -xzf <tarball> -C <destDir>
		const tarCmd = platform() === "win32" ? "tar.exe" : "tar";
		const r = spawnSync(tarCmd, ["-xzf", tmpTar, "-C", destDir], {
			encoding: "utf-8",
			timeout: 60_000,
		});
		unlinkSync(tmpTar);
		return r.status === 0;
	} catch {
		try { unlinkSync(tmpTar); } catch { /* ignore */ }
		return false;
	}
}

function extractPipelineZip(buf: Buffer, destDir: string): boolean {
	const tmpZip = join(tmpdir(), `aidlc-veracode-pipeline-${Date.now()}.zip`);
	try {
		writeFileSync(tmpZip, buf);
		// POSIX: try tar first (often available), then unzip
		if (platform() !== "win32") {
			const r = spawnSync("tar", ["-xf", tmpZip, "-C", destDir], {
				encoding: "utf-8",
				timeout: 60_000,
			});
			unlinkSync(tmpZip);
			if (r.status === 0) return true;
			// Fallback to unzip
			const r2 = spawnSync("unzip", ["-o", tmpZip, "-d", destDir], {
				encoding: "utf-8",
				timeout: 60_000,
			});
			return r2.status === 0;
		} else {
			// Windows: use tar (supports zip on Win10+)
			const r = spawnSync("tar.exe", ["-xf", tmpZip, "-C", destDir], {
				encoding: "utf-8",
				timeout: 60_000,
			});
			unlinkSync(tmpZip);
			return r.status === 0;
		}
	} catch {
		try { unlinkSync(tmpZip); } catch { /* ignore */ }
		return false;
	}
}

async function ensureCli(cacheDir: string): Promise<string | null> {
	ensureDir(join(cacheDir, "cli"));

	// Check version cache
	const cachedVersion = readCachedVersion(cacheDir);
	let latest = "";
	try {
		const raw = await httpsGet(LATEST_VERSION_URL, 10_000);
		latest = parseLatestVersion(raw);
		if (!latest) return null;
	} catch {
		// If we have a cached binary, use it even without latest check
		if (cachedVersion && binaryExistsAt(cacheDir, cachedVersion)) {
			return join(cacheDir, "cli", cachedVersion, cliBinaryName());
		}
		return null;
	}

	// Fresh cache?
	if (cacheCliFresh(cachedVersion, latest, binaryExistsAt(cacheDir, latest))) {
		return join(cacheDir, "cli", latest, cliBinaryName());
	}

	// Download tarball
	const osArch = cliOsArch(platform(), arch());
	if (!osArch) return null;

	const tarballUrl = `${CLI_DOWNLOAD}/veracode-cli_${latest}_${osArch}.tar.gz`;
	let buf: Buffer;
	try {
		buf = await httpsGetBinary(tarballUrl, 60_000);
	} catch {
		return null;
	}

	// Extract to temp dir, then atomic rename
	const tmpExtract = join(cacheDir, "cli", `.extract-${Date.now()}`);
	const finalDir = join(cacheDir, "cli", latest);
	ensureDir(tmpExtract);

	if (!extractTarball(buf, tmpExtract)) {
		try { rmDir(tmpExtract); } catch { /* ignore */ }
		return null;
	}

	// The tarball may extract into a subdirectory; find the binary
	const binName = cliBinaryName();
	let foundBin = join(tmpExtract, binName);
	if (!existsSync(foundBin)) {
		// Search one level deep
		try {
			const entries = readdirSync(tmpExtract);
			for (const entry of entries) {
				const candidate = join(tmpExtract, entry, binName);
				if (existsSync(candidate)) {
					foundBin = candidate;
					break;
				}
			}
		} catch { /* ignore */ }
	}

	if (!existsSync(foundBin)) {
		try { rmDir(tmpExtract); } catch { /* ignore */ }
		return null;
	}

	// Flatten: copy binary to a known flat path regardless of tarball layout
	try {
		if (existsSync(finalDir)) rmDir(finalDir);
		ensureDir(finalDir);
		const destBin = join(finalDir, binName);
		copyFileSync(foundBin, destBin);
		if (platform() !== "win32") {
			try { chmodSync(destBin, 0o755); } catch { /* ignore */ }
		}
	} catch {
		try { rmDir(tmpExtract); } catch { /* ignore */ }
		return null;
	}

	// Discard the extract tree
	try { rmDir(tmpExtract); } catch { /* ignore */ }

	// Write VERSION file
	try {
		writeFileSync(join(cacheDir, "cli", "VERSION"), latest);
	} catch { /* ignore */ }

	return join(finalDir, binName);
}

function rmDir(p: string): void {
	rmSync(p, { recursive: true, force: true });
}

async function ensurePipelineJar(cacheDir: string): Promise<string | null> {
	ensureDir(join(cacheDir, "pipeline-scan"));

	const stampFile = join(cacheDir, "pipeline-scan", "STAMP");
	const jarPath = join(cacheDir, "pipeline-scan", "pipeline-scan.jar");

	// If jar exists and stamp is recent (< 24h), reuse
	if (existsSync(jarPath) && existsSync(stampFile)) {
		try {
			const stamp = parseInt(readFileSync(stampFile, "utf-8").trim(), 10);
			const age = Date.now() - stamp;
			if (age < 24 * 60 * 60 * 1000) return jarPath;
		} catch { /* ignore */ }
	}

	// Download zip
	let buf: Buffer;
	try {
		buf = await httpsGetBinary(PIPELINE_ZIP_URL, 60_000);
	} catch {
		if (existsSync(jarPath)) return jarPath; // fallback to stale
		return null;
	}

	if (!extractPipelineZip(buf, join(cacheDir, "pipeline-scan"))) {
		if (existsSync(jarPath)) return jarPath;
		return null;
	}

	// Write stamp
	try {
		writeFileSync(stampFile, String(Date.now()));
	} catch { /* ignore */ }

	return existsSync(jarPath) ? jarPath : null;
}

// --- probe java (runtime, still needed for jar fallback) --------------------

function probeJava(): boolean {
	const r = spawnSync("java", ["-version"], {
		encoding: "utf-8",
		timeout: 15_000,
	});
	return r.status === 0;
}

// --- SAST: Veracode Pipeline Scan -------------------------------------------

interface SastFinding {
	engine: "sast";
	file: string;
	line?: number;
	rule?: string;
	severity: string;
	message: string;
}

interface SastResult {
	ran: boolean;
	tool_unavailable: boolean;
	failBarCount: number;
	findings: SastFinding[];
}

export function parsePipelineScanJson(raw: string, _filePath: string): {
	failBarCount: number;
	findings: SastFinding[];
} {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return { failBarCount: 0, findings: [] };
	}
	if (!parsed || typeof parsed !== "object") return { failBarCount: 0, findings: [] };
	const findingsArr = (parsed as Record<string, unknown>).findings;
	if (!Array.isArray(findingsArr)) return { failBarCount: 0, findings: [] };

	let failBarCount = 0;
	const findings: SastFinding[] = [];
	for (const f of findingsArr) {
		const rec = f as Record<string, unknown>;
		const sevRaw = rec.severity;
		const severity = typeof sevRaw === "number" ? String(sevRaw) : String(sevRaw ?? "");
		const isFail = severityIsFailBar(sevRaw);
		if (isFail) failBarCount++;

		const filesObj = (rec.files ?? {}) as Record<string, unknown>;
		const srcFile = (filesObj.source_file ?? {}) as Record<string, unknown>;
		const file = String(srcFile.file ?? "");
		const line = typeof srcFile.line === "number" ? srcFile.line : undefined;

		findings.push({
			engine: "sast",
			file,
			line,
			rule: rec.cwe_id ? `CWE-${rec.cwe_id}` : String(rec.title ?? ""),
			severity: String(sevRaw ?? ""),
			message: String(rec.title ?? ""),
		});
	}
	return { failBarCount, findings };
}

function runSastWithCli(cliPath: string, artifact: string): SastResult {
	const tmpFile = `${tmpdir()}/aidlc-sca-sast-${Date.now()}.json`;
	const result = spawnSync(cliPath, [
		"static", "scan", artifact,
		"--results-file", tmpFile,
		"--fail-on-severity", "Very High, High",
	], { encoding: "utf-8", timeout: 180_000 });

	// Check for 401 auth failure
	if (result.stderr?.includes("401") || result.stdout?.includes("401")) {
		return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	// Try to read results file
	if (existsSync(tmpFile)) {
		try {
			const raw = readFileSync(tmpFile, "utf-8");
			const { failBarCount, findings } = parsePipelineScanJson(raw, artifact);
			return { ran: true, tool_unavailable: false, failBarCount, findings };
		} catch {
			// best-effort unlink
		} finally {
			try { unlinkSync(tmpFile); } catch { /* best-effort */ }
		}
	}

	// No results file — inspect exit code + stdout
	const status = result.status ?? -1;
	const stdout = result.stdout?.trim() ?? "";

	// Try parsing stdout as JSON findings
	if (stdout) {
		const parsed = parsePipelineScanJson(stdout, artifact);
		if (parsed.findings.length > 0) {
			return { ran: true, tool_unavailable: false, failBarCount: parsed.failBarCount, findings: parsed.findings };
		}
	}

	if (status === 3) {
		// Veracode exit 3 = flaws matched fail criteria, no parseable output
		process.stderr.write("veracode-sast-bad-output\n");
		process.exit(1);
	}

	if (status !== 0) {
		// Non-zero, non-3 → tool error → degrade as unavailable
		return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	// Exit 0, no file, no parseable stdout → tool produced nothing → unavailable
	return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
}

function runSastWithJar(jarPath: string, artifact: string): SastResult {
	const tmpFile = `${tmpdir()}/aidlc-sca-sast-${Date.now()}.json`;
	const result = spawnSync("java", [
		"-jar", jarPath,
		"--file", artifact,
		"--fail_on_severity", "Very High, High",
		"--json_output_file", tmpFile,
	], { encoding: "utf-8", timeout: 180_000 });

	if (result.stderr?.includes("401") || result.stdout?.includes("401")) {
		return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	if (existsSync(tmpFile)) {
		try {
			const raw = readFileSync(tmpFile, "utf-8");
			const { failBarCount, findings } = parsePipelineScanJson(raw, artifact);
			return { ran: true, tool_unavailable: false, failBarCount, findings };
		} catch {
			// best-effort unlink
		} finally {
			try { unlinkSync(tmpFile); } catch { /* best-effort */ }
		}
	}

	// No results file — inspect exit code + stdout
	const status = result.status ?? -1;
	const stdout = result.stdout?.trim() ?? "";

	// Try parsing stdout as JSON findings
	if (stdout) {
		const parsed = parsePipelineScanJson(stdout, artifact);
		if (parsed.findings.length > 0) {
			return { ran: true, tool_unavailable: false, failBarCount: parsed.failBarCount, findings: parsed.findings };
		}
	}

	if (status === 3) {
		// Veracode exit 3 = flaws matched fail criteria, no parseable output
		process.stderr.write("veracode-sast-bad-output\n");
		process.exit(1);
	}

	if (status !== 0) {
		// Non-zero, non-3 → tool error → degrade as unavailable
		return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	// Exit 0, no file, no parseable stdout → tool produced nothing → unavailable
	return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
}

async function runSast(artifact: string, cacheDir: string): Promise<SastResult> {
	// Primary: cached CLI
	const cliPath = await ensureCli(cacheDir);
	if (cliPath) {
		const result = runSastWithCli(cliPath, artifact);
		// If CLI succeeded or failed with parseable output, return
		if (!result.tool_unavailable) return result;
		// CLI ran but was unavailable (e.g. auth error) — propagate
		if (result.ran) return result;
	}

	// Fallback: pipeline-scan.jar
	const jarPath = await ensurePipelineJar(cacheDir);
	if (jarPath && probeJava()) {
		return runSastWithJar(jarPath, artifact);
	}

	return { ran: false, tool_unavailable: true, failBarCount: 0, findings: [] };
}

// --- SCA: Veracode SCA via CLI only (no srcclr) -----------------------------

interface ScaFinding {
	engine: "sca";
	file: string;
	line?: number;
	rule?: string;
	severity: string;
	message: string;
}

interface ScaResult {
	ran: boolean;
	tool_unavailable: boolean;
	failBarCount: number;
	findings: ScaFinding[];
}

// CVSS → severity mapping when explicit severity is absent:
//   >= 9.0 → Very High
//   >= 7.0 → High
//   < 7.0  → Medium
function cvssToSeverity(cvss: number): string {
	if (cvss >= 9) return "Very High";
	if (cvss >= 7) return "High";
	return "Medium";
}

export function parseVeracodeScaJson(raw: string): {
	failBarCount: number;
	findings: ScaFinding[];
} {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error("veracode-sca-bad-output");
	}
	if (!parsed || typeof parsed !== "object") {
		throw new Error("veracode-sca-bad-output");
	}

	let failBarCount = 0;
	const findings: ScaFinding[] = [];

	// Accept records[].vulnerabilities shape
	const records = (parsed as Record<string, unknown>).records;
	if (!Array.isArray(records)) {
		throw new Error("veracode-sca-bad-output");
	}

	for (const rec of records) {
		const pkgRec = rec as Record<string, unknown>;
		const vulns = pkgRec.vulnerabilities;
		if (!Array.isArray(vulns)) continue;
		for (const v of vulns) {
			const vRec = v as Record<string, unknown>;
			let severity = String(vRec.severity ?? "");
			// If no explicit severity, derive from CVSS
			if (!severity) {
				const cvss = Number(vRec.cvss);
				if (!isNaN(cvss)) {
					severity = cvssToSeverity(cvss);
				}
			}
			const isFail = severityIsFailBar(severity);
			if (isFail) failBarCount++;
			findings.push({
				engine: "sca",
				file: String(pkgRec.library ?? pkgRec.name ?? ""),
				rule: String(vRec.id ?? vRec.cve ?? ""),
				severity,
				message: String(vRec.summary ?? vRec.description ?? vRec.id ?? vRec.cve ?? ""),
			});
		}
	}
	return { failBarCount, findings };
}

function findProjectRoot(filePath: string): string | null {
	const abs = resolve(filePath);
	let dir = dirname(abs);
	while (true) {
		if (existsSync(`${dir}/package.json`)) return dir;
		if (existsSync(`${dir}/go.mod`)) return dir;
		if (existsSync(`${dir}/Cargo.toml`)) return dir;
		if (existsSync(`${dir}/pom.xml`)) return dir;
		const parent = dirname(dir);
		if (parent === dir) return null;
		dir = parent;
	}
}

async function runSca(filePath: string, cacheDir: string): Promise<ScaResult> {
	const absPath = resolve(filePath);
	const projectRoot = findProjectRoot(absPath) ?? dirname(absPath);

	const cliPath = await ensureCli(cacheDir);
	if (!cliPath) {
		return { ran: false, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	// Try 1: veracode sca scan --target <projectRoot>
	let result = spawnSync(cliPath, [
		"sca", "scan", "--target", projectRoot,
	], { encoding: "utf-8", timeout: 180_000, cwd: projectRoot });

	if (result.stderr?.includes("401")) {
		return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
	}

	// If CLI rejects, try alternate shape
	if (result.status !== 0 && !result.stdout) {
		result = spawnSync(cliPath, [
			"sca", "--target", projectRoot,
		], { encoding: "utf-8", timeout: 180_000, cwd: projectRoot });

		if (result.stderr?.includes("401")) {
			return { ran: true, tool_unavailable: true, failBarCount: 0, findings: [] };
		}
	}

	if (result.stdout) {
		try {
			const { failBarCount, findings } = parseVeracodeScaJson(result.stdout);
			return { ran: true, tool_unavailable: false, failBarCount, findings };
		} catch (e) {
			if (e instanceof Error && e.message === "veracode-sca-bad-output") {
				process.stderr.write("veracode-sca-bad-output\n");
				process.exit(1);
			}
		}
	}

	// All attempts failed — tool spawned but no parseable output
	return { ran: false, tool_unavailable: true, failBarCount: 0, findings: [] };
}

// --- main -------------------------------------------------------------------

interface SensorOutput {
	pass: boolean;
	findings_count: number;
	sast: { ran: boolean; tool_unavailable: boolean; failBarCount: number };
	sca: { ran: boolean; tool_unavailable: boolean; failBarCount: number };
	findings: (SastFinding | ScaFinding)[];
	notes: string[];
}

export async function main(argv: string[]): Promise<void> {
	const args = parseArgs(argv);

	if (!existsSync(args.filePath)) {
		process.stderr.write(`file-path not found: ${args.filePath}\n`);
		process.exit(1);
	}

	const artifact = resolveSastArtifact(args.filePath);
	const needSca = isLockfilePath(args.filePath);

	// Path doesn't match either category — skip
	if (!artifact && !needSca) {
		const out: SensorOutput = {
			pass: true,
			findings_count: 0,
			sast: { ran: false, tool_unavailable: false, failBarCount: 0 },
			sca: { ran: false, tool_unavailable: false, failBarCount: 0 },
			findings: [],
			notes: ["sast: no-packaged-artifact"],
		};
		process.stdout.write(`${JSON.stringify(out)}\n`);
		process.exit(0);
	}

	// If either half actually runs, require creds
	if (artifact || needSca) {
		if (!hasVeracodeCreds()) {
			process.stderr.write("tool-unavailable\n");
			process.exit(127);
		}
	}

	const cacheDir = resolveCacheDir(args.filePath);
	const notes: string[] = [];
	const allFindings: (SastFinding | ScaFinding)[] = [];

	// SAST half
	let sastResult: SastResult | null = null;
	if (artifact) {
		sastResult = await runSast(artifact, cacheDir);
		allFindings.push(...sastResult.findings);
		if (sastResult.tool_unavailable) {
			notes.push("sast: tool-unavailable");
		}
	}

	// SCA half
	let scaResult: ScaResult | null = null;
	if (needSca) {
		scaResult = await runSca(args.filePath, cacheDir);
		allFindings.push(...scaResult.findings);
		if (scaResult.tool_unavailable) {
			notes.push("sca: tool-unavailable");
		}
	}

	// Exit 127 iff the applicable half's tool is missing
	if (artifact && sastResult?.tool_unavailable && !needSca) {
		process.stderr.write("tool-unavailable\n");
		process.exit(127);
	}
	if (needSca && scaResult?.tool_unavailable && !artifact) {
		process.stderr.write("tool-unavailable\n");
		process.exit(127);
	}
	// Both needed and both missing
	if (artifact && needSca && sastResult?.tool_unavailable && scaResult?.tool_unavailable) {
		process.stderr.write("tool-unavailable\n");
		process.exit(127);
	}

	const sastFailBar = sastResult?.failBarCount ?? 0;
	const scaFailBar = scaResult?.failBarCount ?? 0;
	const pass = sastFailBar === 0 && scaFailBar === 0;
	const findings_count = sastFailBar + scaFailBar;

	const out: SensorOutput = {
		pass,
		findings_count,
		sast: {
			ran: sastResult?.ran ?? false,
			tool_unavailable: sastResult?.tool_unavailable ?? false,
			failBarCount: sastFailBar,
		},
		sca: {
			ran: scaResult?.ran ?? false,
			tool_unavailable: scaResult?.tool_unavailable ?? false,
			failBarCount: scaFailBar,
		},
		findings: allFindings,
		notes,
	};
	process.stdout.write(`${JSON.stringify(out)}\n`);
	process.exit(0);
}

if (import.meta.main) main(process.argv.slice(2));
