import crypto from "crypto";

/**
 * Crash Collector & Parser for Android crash logs and tombstones.
 */
export class CrashCollector {
  /**
   * Parses raw crash logcat/tombstone text into structured crash details.
   */
  static parseCrash(rawCrash, metadata = {}) {
    if (!rawCrash || typeof rawCrash !== "string") {
      throw new Error("Invalid crash text provided to CrashCollector");
    }

    const processMatch = rawCrash.match(/>>>\s+([^<\s]+)\s+<<</) || rawCrash.match(/name:\s+([^\s]+)/);
    const processName = processMatch ? processMatch[1] : (metadata.simulatedMeta?.process || "unknown_process");

    const signalMatch = rawCrash.match(/signal\s+\d+\s*\(([^)]+)\)[^,]*(?:,\s*code\s+\d+\s*\(([^)]+)\))?/i);
    const signal = signalMatch 
      ? `${signalMatch[1]}${signalMatch[2] ? ` (${signalMatch[2]})` : ""}` 
      : (metadata.simulatedMeta?.signal || "UNKNOWN_SIGNAL");

    const faultAddrMatch = rawCrash.match(/fault addr\s+([0-9a-fA-Fx]+)/i);
    const faultAddress = faultAddrMatch ? faultAddrMatch[1] : (metadata.simulatedMeta?.faultAddress || "0x0");

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
    const signatureBasis = backtraceLines.slice(0, 3).join("|") || `${processName}-${signal}-${faultAddress}`;
    const hash = crypto.createHash("sha256").update(signatureBasis).digest("hex").substring(0, 8).toUpperCase();
    const crashId = `CRASH-2024-${hash}`;

    const date = metadata.timestamp ? metadata.timestamp.split("T")[0] : new Date().toISOString().split("T")[0];

    return {
      crash_id: crashId,
      process: processName,
      signal,
      fault_address: faultAddress,
      cause,
      backtrace,
      raw_log: rawCrash,
      target_build: metadata.targetBuild || "Android 15 (VanillaIceCream)",
      date,
      source: "fuzzer"
    };
  }

  /**
   * Batches parsing of multiple crash instances.
   */
  static processAll(crashes) {
    return crashes.map(c => this.parseCrash(c.rawCrash, c));
  }
}
