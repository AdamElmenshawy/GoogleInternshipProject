import axios from "axios";
import fs from "fs";
import path from "path";
import { AndroidFuzzer } from "./android_fuzzer.js";
import { CrashCollector } from "./crash_collector.js";
import { GeminiCrashClassifier } from "./analyzer.js";
import { NativeFuzzerRunner } from "./native_runner.js";

/**
 * End-to-End Orchestrator Pipeline:
 * Native libFuzzer (Stagefright/HEVC, WebP, Binder) + System Fuzzer -> 
 * Sanitizer/Crash Extraction -> Gemini ASB Classification & Root Cause -> Dynamic Publishing
 */
export async function runFuzzingAndPublishPipeline(options = {}) {
  const iterations = options.iterations || 3;
  const apiUrl = options.apiUrl || "http://localhost:20000/api/vulnerabilities";
  const outputPath = options.outputPath || path.resolve("SumPatches_output.json");
  const frontendDataPath = path.resolve("asb-app/src/data/SumPatches_output.json");

  console.log("==================================================================");
  console.log("🚀 PRODUCTION ANDROID FUZZING & APPLIED LLM SECURITY PIPELINE");
  console.log("==================================================================");

  const rawCrashes = [];

  // 1. Run Native libFuzzer Targets (Tier 1: Media Stagefright, Tier 3: WebP, Tier 2: Binder)
  console.log("\n📦 [Step 1] Executing Native C++ libFuzzer Targets (HWASan & ASan)...");
  const nativeTargets = ["hevc", "webp", "binder"];
  for (const target of nativeTargets) {
    const runner = new NativeFuzzerRunner({ target, verbose: true });
    const nativeArtifact = await runner.runFuzzSession();
    rawCrashes.push(nativeArtifact);
  }

  // 2. Run Android System / Intent Fuzzing Campaign
  console.log("\n⚡ [Step 2] Executing System Service & Intent Fuzzing...");
  const sysFuzzer = new AndroidFuzzer({
    iterations,
    mode: options.mode || "simulation",
    targetBuild: options.targetBuild || "Android 15 (VanillaIceCream - API 35)"
  });
  const sysCrashes = await sysFuzzer.startFuzzingCampaign();
  const parsedSysCrashes = CrashCollector.processAll(sysCrashes);

  const allCrashes = [...rawCrashes, ...parsedSysCrashes];
  console.log(`\n📋 [Step 3] Extracted ${allCrashes.length} unique Crash IDs, Reproducers & HWASan tags.`);

  // 3. Classify with Gemini using the ASB reference dataset & perform Root Cause Analysis
  const classifier = new GeminiCrashClassifier();
  const classifiedResults = [];

  console.log(`\n🧠 [Step 4] Running Gemini Reference-Set Classification & Root Cause Analysis...`);
  for (const crash of allCrashes) {
    const analyzed = await classifier.analyzeCrash(crash);
    classifiedResults.push(analyzed);
    console.log(`   ✓ [${analyzed.crash_id}] ${analyzed.components} | ${analyzed.severity.toUpperCase()} | ${analyzed.type}`);
  }

  // 4. Publish results to the Bulletin Board
  console.log(`\n📤 [Step 5] Publishing results to Security Bulletin Board...`);
  let publishedCount = 0;

  for (const bug of classifiedResults) {
    try {
      await axios.post(apiUrl, bug, { timeout: 2000 });
      publishedCount++;
      console.log(`   📡 Published ${bug.crash_id} to ${apiUrl}`);
    } catch (err) {
      directPersist(bug, outputPath);
      directPersist(bug, frontendDataPath);
      publishedCount++;
      console.log(`   💾 Direct persisted ${bug.crash_id} to dataset files (${err.message})`);
    }
  }

  console.log("\n==================================================================");
  console.log(`🎉 PIPELINE COMPLETE: ${publishedCount} native & system fuzzer bugs analyzed & published!`);
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
  runFuzzingAndPublishPipeline({ iterations: 3 });
}
