import axios from "axios";
import fs from "fs";
import path from "path";
import { AndroidFuzzer } from "./android_fuzzer.js";
import { CrashCollector } from "./crash_collector.js";
import { GeminiCrashClassifier } from "./analyzer.js";
import { NativeFuzzerRunner } from "./native_runner.js";
import { generateVRPReport } from "./vrp_reporter.js";

/**
 * End-to-End Orchestrator Pipeline:
 * Native libFuzzer (Stagefright/HEVC, WebP, Binder) + System Fuzzer ->
 * Crash Collection (tombstones + crash inputs) -> Minimization ->
 * Gemini ASB Classification & Root Cause -> VRP Report -> Publish.
 *
 * Trust rules:
 *   - Default mode is "device". Simulation/dry-run must be explicitly opted
 *     into and every simulated artifact is marked source:"simulation" — the
 *     pipeline refuses to ingest simulated data as a real finding.
 *   - A crash is only reported if the fuzzer actually produced one.
 *   - Analysis requires Gemini; there is no heuristic fallback.
 */
export async function runFuzzingAndPublishPipeline(options = {}) {
  const iterations = options.iterations || 3;
  const apiUrl = options.apiUrl || "http://localhost:20000/api/crashes";
  const outputPath = options.outputPath || path.resolve("SumPatches_output.json");
  const frontendDataPath = path.resolve("asb-app/src/data/SumPatches_output.json");

  const mode = options.mode || process.env.FUZZER_MODE || "device";
  const dryRun = mode === "simulation" || mode === "dry-run";

  // Simulation is disabled by default — it must be explicitly opted into.
  if (dryRun && !options.simulationAllowed && process.env.FUZZER_MODE !== "simulation") {
    throw new Error(
      "Simulation mode is disabled. Set FUZZER_MODE=simulation (or pass --dry-run) explicitly to override."
    );
  }

  console.log("==================================================================");
  console.log("🚀 PRODUCTION ANDROID FUZZING & APPLIED LLM SECURITY PIPELINE");
  console.log(`   Mode: ${mode.toUpperCase()}${dryRun ? " (DRY-RUN — simulated artifacts will NOT be ingested as findings)" : ""}`);
  console.log("==================================================================");

  const rawCrashes = [];

  // 1. Run Native libFuzzer Targets (Tier 1: Media Stagefright, Tier 3: WebP, Tier 2: Binder)
  console.log("\n📦 [Step 1] Executing Native C++ libFuzzer Targets (HWASan & ASan)...");
  const nativeTargets = ["hevc", "webp", "binder"];
  for (const target of nativeTargets) {
    const runner = new NativeFuzzerRunner({
      target,
      mode: dryRun ? "dry-run" : "device",
      simulationAllowed: dryRun,
      verbose: true,
    });
    const artifacts = await runner.runFuzzSession();
    rawCrashes.push(...artifacts);
  }

  // 2. Run Android System / Intent Fuzzing Campaign (device mode only)
  if (!dryRun) {
    console.log("\n⚡ [Step 2] Executing System Service & Intent Fuzzing...");
    const sysFuzzer = new AndroidFuzzer({
      iterations,
      mode: "device",
      targetBuild: options.targetBuild || "Android 15 (VanillaIceCream - API 35)",
    });
    const sysCrashes = await sysFuzzer.startFuzzingCampaign();
    const parsedSysCrashes = CrashCollector.processAll(sysCrashes);
    rawCrashes.push(...parsedSysCrashes);
  } else {
    console.log("\n⚡ [Step 2] Skipping system fuzzing in dry-run mode.");
  }

  // Refuse to ingest simulated artifacts as real findings.
  const realCrashes = rawCrashes.filter(c => !c.simulated);
  const simulatedCount = rawCrashes.length - realCrashes.length;
  if (simulatedCount > 0) {
    console.log(`\n⚠️  [Step 3] Dropping ${simulatedCount} simulated artifact(s) — they are NOT findings.`);
  }

  console.log(`\n📋 [Step 3] Extracted ${realCrashes.length} real crash artifact(s).`);

  if (realCrashes.length === 0) {
    console.log("\n✅ No crashes surfaced. Pipeline complete (nothing to analyze or publish).");
    return [];
  }

  // 3. Minimize each crash input before analysis (required for VRP).
  console.log(`\n🔬 [Step 4] Minimizing crash reproducers...`);
  const collector = new CrashCollector();
  const minimizedCrashes = [];
  for (const crash of realCrashes) {
    try {
      const minResult = collector.minimizeCrash(
        crash.reproducer_path || crash.reproducer_hex,
        `./artifacts/minimized/${crash.crash_id}`,
        { target: crash.target, arch: options.arch || "arm64" }
      );
      crash.minimized_inputs = minResult.minimizedInputs;
      crash.status = "ingested";
      minimizedCrashes.push(crash);
    } catch (err) {
      console.warn(`[Pipeline] Minimization skipped for ${crash.crash_id}: ${err.message}`);
      minimizedCrashes.push(crash);
    }
  }

  // 4. Classify with Gemini using the ASB reference dataset & perform Root Cause Analysis.
  const classifier = new GeminiCrashClassifier();
  const classifiedResults = [];

  console.log(`\n🧠 [Step 5] Running Gemini Reference-Set Classification & Root Cause Analysis...`);
  for (const crash of minimizedCrashes) {
    try {
      const analyzed = await classifier.analyzeCrash(crash);
      classifiedResults.push(analyzed);
      console.log(`   ✓ [${analyzed.crash_id}] ${analyzed.components} | ${analyzed.severity.toUpperCase()} | ${analyzed.type} (conf ${analyzed.confidence})`);
    } catch (err) {
      console.error(`   ✗ [${crash.crash_id}] Analysis failed: ${err.message}`);
      // Never silently accept or discard — record it for the retry queue.
      classifiedResults.push({
        ...crash,
        status: "ingested",
        analysis_status: "pending_retry",
        analysis_error: err.message,
      });
    }
  }

  // 5. Generate VRP reports for analyzed crashes.
  console.log(`\n📄 [Step 6] Generating VRP reports...`);
  const vrpReports = [];
  for (const bug of classifiedResults) {
    if (bug.analysis_status === "pending_retry") {
      vrpReports.push({ bug, vrpReport: null, note: "pending_retry" });
      continue;
    }
    const vrpReport = generateVRPReport(bug, bug);
    vrpReports.push({ bug, vrpReport });
    bug.status = "pending_review";
    bug.vrp_report = vrpReport;
  }

  // 6. Publish results to the Bulletin Board (pending_review — not yet findings).
  console.log(`\n📤 [Step 7] Publishing results to Security Bulletin Board (status: pending_review)...`);
  let publishedCount = 0;

  for (const { bug } of vrpReports) {
    try {
      await axios.post(apiUrl, bug, { timeout: 2000 });
      publishedCount++;
      console.log(`   📡 Published ${bug.crash_id} to ${apiUrl} (status: ${bug.status})`);
    } catch (err) {
      directPersist(bug, outputPath);
      directPersist(bug, frontendDataPath);
      publishedCount++;
      console.log(`   💾 Direct persisted ${bug.crash_id} to dataset files (${err.message})`);
    }
  }

  console.log("\n==================================================================");
  console.log(`🎉 PIPELINE COMPLETE: ${publishedCount} crashes analyzed & queued for review.`);
  console.log("   Nothing is a finding until a human publishes it (status: published).");
  console.log("==================================================================");

  return classifiedResults;
}

function directPersist(item, filePath) {
  try {
    let existing = [];
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, "utf-8").trim();
      if (content) {
        existing = JSON.parse(content);
      }
    }

    const idx = existing.findIndex(e => (e.cve_id === item.cve_id || e.crash_id === item.cve_id));
    if (idx >= 0) {
      existing[idx] = item;
    } else {
      existing.unshift(item);
    }

    fs.writeFileSync(filePath, JSON.stringify(existing, null, 2));
  } catch (err) {
    console.error(`Failed to persist directly to ${filePath}:`, err.message);
  }
}

if (process.argv[1] && process.argv[1].endsWith("pipeline.js")) {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run") || args.includes("-d");
  const mode = process.env.FUZZER_MODE || (dryRun ? "dry-run" : "device");
  runFuzzingAndPublishPipeline({
    iterations: 3,
    mode,
    simulationAllowed: dryRun || process.env.FUZZER_MODE === "simulation",
  }).catch(err => {
    console.error(`[Pipeline] ${err.message}`);
    process.exit(1);
  });
}
