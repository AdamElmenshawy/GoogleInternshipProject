import crypto from "crypto";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";

/**
 * Crash Collector & Parser for Android crash logs and tombstones.
 *
 * Real HWASan/ASan crashes on a userdebug device produce two artifacts:
 *   1. A crash tombstone at /data/tombstones/tombstone_NN
 *   2. A libFuzzer crash input at /data/fuzz/<arch>/<target>/crash-<hash>
 *
 * This module pulls both, parses the tombstone into structured fields, and
 * minimizes the reproducer input with libFuzzer's -minimize_crash.
 */
export class CrashCollector {
  /**
   * Parses raw crash logcat/tombstone text into structured crash details.
   * All output fields are snake_case (matches the ASB schema and the rest of
   * the pipeline).
   */
  static parseCrash(rawCrash, metadata = {}) {
    if (!rawCrash || typeof rawCrash !== "string") {
      throw new Error("Invalid crash text provided to CrashCollector");
    }

    const processMatch = rawCrash.match(/>>>\s+([^<\s]+)\s+<<</) || rawCrash.match(/name:\s+([^\s]+)/);
    const process_name = processMatch ? processMatch[1] : (metadata.simulatedMeta?.process || "unknown_process");

    const signalMatch = rawCrash.match(/signal\s+\d+\s*\(([^)]+)\)[^,]*(?:,\s*code\s+\d+\s*\(([^)]+)\))?/i);
    const signal = signalMatch
      ? `${signalMatch[1]}${signalMatch[2] ? ` (${signalMatch[2]})` : ""}`
      : (metadata.simulatedMeta?.signal || "UNKNOWN_SIGNAL");

    const signalCodeMatch = rawCrash.match(/signal\s+\d+\s*\(([^)]+)\),\s*code\s+(-?\d+)\s*\(([^)]+)\)/i);
    const signal_code = signalCodeMatch ? signalCodeMatch[2] : null;

    const faultAddrMatch = rawCrash.match(/fault addr\s+([0-9a-fA-Fx]+)/i);
    const fault_address = faultAddrMatch ? faultAddrMatch[1] : (metadata.simulatedMeta?.faultAddress || "0x0");

    const causeMatch = rawCrash.match(/Cause:\s+([^\n]+)/i) || rawCrash.match(/Abort message:\s*'([^']+)'/i);
    const cause = causeMatch ? causeMatch[1] : (metadata.simulatedMeta?.summaryType || "Unknown abort/crash cause");

    // Extract backtrace frames
    const backtraceLines = [];
    const frameRegex = /#\d+\s+pc\s+[0-9a-fA-F]+\s+([^\n\r]+)/g;
    let match;
    while ((match = frameRegex.exec(rawCrash)) !== null) {
      backtraceLines.push(match[0].trim());
    }

    const backtrace = backtraceLines.length > 0 ? backtraceLines.join("\n") : "No backtrace frames found";

    // Generate deterministic Crash ID from top 3 frames or process + signal
    const signatureBasis = backtraceLines.slice(0, 3).join("|") || `${process_name}-${signal}-${fault_address}`;
    const hash = crypto.createHash("sha256").update(signatureBasis).digest("hex").substring(0, 8).toUpperCase();
    const crash_id = `CRASH-2024-${hash}`;

    const date = metadata.timestamp ? metadata.timestamp.split("T")[0] : new Date().toISOString().split("T")[0];

    return {
      crash_id,
      cve_id: crash_id,
      process: process_name,
      process_name,
      signal,
      signal_code,
      fault_address,
      cause,
      backtrace,
      raw_log: rawCrash,
      target_build: metadata.target_build || metadata.targetBuild || "Android 15 (VanillaIceCream)",
      date,
      source: metadata.source || "fuzzer",
      status: "ingested",
      // True only for dry-run fixtures; the pipeline refuses to ingest these as findings.
      simulated: metadata.simulated || false,
    };
  }

  /**
   * Batches parsing of multiple crash instances.
   */
  static processAll(crashes) {
    return crashes.map(c => this.parseCrash(c.rawCrash, c));
  }

  /**
   * Reads a tombstone file from disk and parses it into structured fields.
   */
  static parseTombstone(tombstonePath, metadata = {}) {
    if (!fs.existsSync(tombstonePath)) {
      throw new Error(`Tombstone not found: ${tombstonePath}`);
    }
    const raw = fs.readFileSync(tombstonePath, "utf-8");
    const parsed = this.parseCrash(raw, metadata);
    parsed.tombstone_path = tombstonePath;
    return parsed;
  }

  /**
   * Lists tombstones on the device, newest first.
   * Returns an array of tombstone filenames (e.g. ['tombstone_05', ...]).
   */
  listTombstones(limit = 5) {
    const { stdout } = execSync(`adb shell ls -lt /data/tombstones | head -${limit + 1}`, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return stdout
      .trim()
      .split("\n")
      .map(line => line.split(/\s+/).pop())
      .filter(f => f && f.startsWith("tombstone_"));
  }

  /**
   * Pulls the N most recent tombstones from the device into localDir.
   * Returns the list of pulled filenames.
   */
  pullTombstones(localDir, limit = 5) {
    fs.mkdirSync(localDir, { recursive: true });
    const tombstoneFiles = this.listTombstones(limit);
    const pulled = [];
    for (const f of tombstoneFiles) {
      try {
        execSync(`adb pull /data/tombstones/${f} ${path.join(localDir, f)}`, {
          stdio: ["ignore", "pipe", "pipe"],
        });
        pulled.push(f);
      } catch (err) {
        console.warn(`[CrashCollector] Failed to pull ${f}: ${err.message}`);
      }
    }
    return pulled;
  }

  /**
   * Runs libFuzzer's -minimize_crash on a crash input on the device and pulls
   * the minimized artifact. Minimization is required for a VRP submission —
   * an unminimized crash input is noise.
   *
   * @param {string} crashInput  on-device path to the crash-<hash> reproducer
   * @param {string} outputDir   local directory to pull minimized artifacts into
   * @param {string} arch        device ABI, e.g. 'arm64' or 'x86_64'
   */
  minimizeCrash(crashInput, outputDir, { target, arch = "arm64" } = {}) {
    if (!target) throw new Error("minimizeCrash requires the fuzzer target name");
    fs.mkdirSync(outputDir, { recursive: true });

    const onDeviceBinary = `/data/fuzz/${arch}/${target}/${target}`;
    const onDeviceOut = "/data/fuzz/minimized/";
    const cmd = [
      `adb shell ${onDeviceBinary}`,
      `-minimize_crash=1`,
      `-artifact_prefix=${onDeviceOut}`,
      crashInput,
    ].join(" ");

    console.log(`[CrashCollector] Minimizing crash: ${cmd}`);
    try {
      execSync(cmd, { stdio: ["ignore", "pipe", "pipe"], timeout: 120000 });
    } catch (err) {
      // libFuzzer exits non-zero after minimization; that is expected.
      console.log(`[CrashCollector] Minimizer finished (exit ${err.status}).`);
    }

    // Pull any minimized artifacts produced.
    const pulled = [];
    try {
      const { stdout } = execSync(`adb shell ls ${onDeviceOut}`, { encoding: "utf-8" });
      const files = stdout.trim().split("\n").filter(Boolean);
      for (const f of files) {
        execSync(`adb pull ${onDeviceOut}${f} ${path.join(outputDir, f)}`, { stdio: ["ignore", "pipe", "pipe"] });
        pulled.push(path.join(outputDir, f));
      }
    } catch (err) {
      console.warn(`[CrashCollector] No minimized artifacts pulled: ${err.message}`);
    }

    return { outputDir, minimizedInputs: pulled };
  }
}
