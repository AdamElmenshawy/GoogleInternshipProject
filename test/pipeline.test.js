import { test } from "node:test";
import assert from "node:assert/strict";
import { CrashCollector } from "../fuzzer/crash_collector.js";
import { generateVRPReport } from "../fuzzer/vrp_reporter.js";
import { isValidAsbId, guessComponent, validateAnalysis } from "../fuzzer/analyzer.js";
import { isValidTransition, CRASH_STATUS_FLOW } from "../fuzzer/status_machine.js";

const SAMPLE_TOMBSTONE = `*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/akita/akita:15/AP3A.241005.015/12345678:userdebug/dev-keys'
Revision: 'MP1.0'
ABI: 'arm64'
Timestamp: 2024-01-15 10:00:00.000000000+0000
pid: 890, tid: 1104, name: Codec2-worker  >>> /system/bin/mediacodec <<<
uid: 1046
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000007412984000
Cause: heap buffer overflow during HEVC slice header parsing
    x0  0000000000000000  x1  00000078b4a21980  x2  0000000000000001  x3  00000078b4a21a00
    sp  00000078b27fe8a0  lr  0000007b8a1e5820  pc  0000007b8a1e5844  pst 0000000060001000
backtrace:
      #00 pc 00000000000a474c  /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so (ihevcd_parse_slice_header+620)
      #01 pc 000000000009ec30  /apex/com.android.media.swcodec/lib64/libstagefright_soft_c2hevcdec.so (ihevcd_decode+1480)
      #02 pc 0000000000085110  /apex/com.android.media.swcodec/lib64/libcodec2_soft_common.so (C2SoftHevcDec::process+410)`;

test("CrashCollector.parseCrash extracts tombstone fields", () => {
  const parsed = CrashCollector.parseCrash(SAMPLE_TOMBSTONE, { target_build: "Android 15" });

  assert.equal(parsed.process, "/system/bin/mediacodec");
  assert.equal(parsed.process_name, "/system/bin/mediacodec");
  assert.match(parsed.signal, /SIGSEGV/);
  assert.equal(parsed.signal_code, "1");
  assert.equal(parsed.fault_address, "0x0000007412984000");
  assert.match(parsed.cause, /heap buffer overflow/);
  assert.match(parsed.backtrace, /ihevcd_parse_slice_header/);
  assert.match(parsed.crash_id, /^CRASH-2024-/);
  assert.equal(parsed.status, "ingested");
  assert.equal(parsed.simulated, false);
});

test("CrashCollector.parseCrash marks simulated artifacts", () => {
  const parsed = CrashCollector.parseCrash("signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0", {
    source: "simulation",
    simulated: true,
    simulatedMeta: { process: "system_server", signal: "SIGSEGV", faultAddress: "0x0", summaryType: "test" },
  });
  assert.equal(parsed.source, "simulation");
  assert.equal(parsed.simulated, true);
});

test("CrashCollector.parseCrash rejects non-string input", () => {
  assert.throws(() => CrashCollector.parseCrash(null), /Invalid crash text/);
});

test("generateVRPReport leaves human-verification fields blank", () => {
  const crash = {
    crash_id: "CRASH-2024-ABC123",
    process: "/system/bin/mediacodec",
    fault_address: "0x0000007412984000",
    reproducer_path: "/tmp/minimized.bin",
    raw_log: "==ERROR== HWAddressSanitizer ...",
    target: "hevc_extractor_fuzzer",
  };
  const analysis = {
    component: "Media / Codec",
    vulnerability_type: "Memory Corruption",
    severity: "high",
    confidence: 0.9,
    root_cause_hypothesis: "Heap OOB in HEVC slice parser",
    supporting_frames: ["#00 ihevcd_parse_slice_header"],
    reference_ids: [],
    missing_evidence: ["minimized reproducer"],
    model_version: "gemini-2.5-flash",
  };

  const report = generateVRPReport(crash, analysis);

  assert.equal(report.title, "Memory Corruption in Media / Codec (high)");
  assert.equal(report.impact.affectedVersions, "REQUIRES HUMAN VERIFICATION");
  assert.equal(report.impact.securityImpact, "REQUIRES HUMAN ASSESSMENT");
  assert.equal(report.reproduction.build_fingerprint, "REQUIRES HUMAN VERIFICATION");
  assert.match(report.aiAnalysisNote, /triage aid/);
  assert.equal(report.evidence.reproducerInput, "/tmp/minimized.bin");
});

test("isValidAsbId accepts only real bulletin IDs", () => {
  assert.equal(isValidAsbId("ASB-A-135368228"), true);
  assert.equal(isValidAsbId("PUB-A-123456"), true);
  assert.equal(isValidAsbId("CVE-2023-4863"), true);
  assert.equal(isValidAsbId("CRASH-2024-ABC"), false);
  assert.equal(isValidAsbId(undefined), false);
  assert.equal(isValidAsbId(""), false);
});

test("guessComponent maps process names to sections", () => {
  assert.equal(guessComponent("/system/bin/netd"), "kernel");
  assert.equal(guessComponent("/vendor/bin/hw/bluetooth"), "vendor");
  assert.equal(guessComponent("/apex/.../libstagefright_soft_c2hevcdec.so"), "media");
  assert.equal(guessComponent("/system/bin/surfaceflinger"), "framework");
  assert.equal(guessComponent("com.android.settings"), "");
});

test("validateAnalysis enforces the schema contract", () => {
  const good = {
    component: "Media / Codec",
    vulnerability_type: "Memory Corruption",
    severity: "high",
    confidence: 0.9,
    root_cause_hypothesis: "Heap OOB",
    supporting_frames: ["#00 frame"],
    reference_ids: [],
    missing_evidence: [],
  };
  assert.equal(validateAnalysis(good), true);

  assert.equal(validateAnalysis(null), false);
  assert.equal(validateAnalysis({ ...good, vulnerability_type: "NotARealType" }), false);
  assert.equal(validateAnalysis({ ...good, severity: "catastrophic" }), false);
  assert.equal(validateAnalysis({ ...good, confidence: 1.5 }), false);
  assert.equal(validateAnalysis({ ...good, supporting_frames: "not-an-array" }), false);
});

test("isValidTransition enforces forward-only lifecycle", () => {
  // Forward moves are legal.
  assert.equal(isValidTransition("ingested", "analyzed"), true);
  assert.equal(isValidTransition("analyzed", "pending_review"), true);
  assert.equal(isValidTransition("pending_review", "published"), true);

  // Same-state updates are idempotent (legal).
  for (const state of CRASH_STATUS_FLOW) {
    assert.equal(isValidTransition(state, state), true, `${state} → ${state} should be idempotent`);
  }

  // Backward moves are illegal.
  assert.equal(isValidTransition("analyzed", "ingested"), false);
  assert.equal(isValidTransition("published", "ingested"), false);
  assert.equal(isValidTransition("published", "pending_review"), false);

  // Rejection is allowed from any pre-published state.
  assert.equal(isValidTransition("ingested", "rejected"), true);
  assert.equal(isValidTransition("pending_review", "rejected"), true);
  // But NOT from published (published is terminal).
  assert.equal(isValidTransition("published", "rejected"), false);

  // Once rejected, no forward move is allowed (rejected is terminal).
  assert.equal(isValidTransition("rejected", "analyzed"), false);
  assert.equal(isValidTransition("rejected", "published"), false);
});

test("CrashCollector.parseCrash generates deterministic crash_id", () => {
  // Same input → same crash_id (deterministic hash).
  const a = CrashCollector.parseCrash(SAMPLE_TOMBSTONE, {});
  const b = CrashCollector.parseCrash(SAMPLE_TOMBSTONE, {});
  assert.equal(a.crash_id, b.crash_id, "crash_id must be deterministic for the same input");

  // Different input → different crash_id.
  const other = CrashCollector.parseCrash(
    SAMPLE_TOMBSTONE.replace("ihevcd_parse_slice_header", "webp_decode"),
    {}
  );
  assert.notEqual(a.crash_id, other.crash_id, "crash_id must differ for different backtraces");
});
