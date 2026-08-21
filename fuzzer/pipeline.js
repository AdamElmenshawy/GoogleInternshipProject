import axios from "axios";
import fs from "fs";
import path from "path";
import { AndroidFuzzer } from "./android_fuzzer.js";
import { CrashCollector } from "./crash_collector.js";
import { GeminiCrashClassifier } from "./analyzer.js";

/**
 * End-to-End Orchestrator Pipeline:
 * Fuzz -> Collect Crash -> Gemini Classify & Root Cause -> Publish to Bulletin Board
 */
export async function runFuzzingAndPublishPipeline(options = {}) {
  const iterations = options.iterations || 4;
  const apiUrl = options.apiUrl || "http://localhost:20000/api/vulnerabilities";
  const outputPath = options.outputPath || path.resolve("SumPatches_output.json");
  const frontendDataPath = path.resolve("asb-app/src/data/SumPatches_output.json");

  console.log("==================================================================");
  console.log("🚀 STARTING ANDROID FUZZING & SECURITY BULLETIN PIPELINE");
  console.log("==================================================================");

  // 1. Run Android Fuzzer
  const fuzzer = new AndroidFuzzer({
    iterations,
    mode: options.mode || "simulation",
    targetBuild: options.targetBuild || "Android 15 (VanillaIceCream - API 35)"
  });

  const rawCrashes = await fuzzer.startFuzzingCampaign();
  console.log(`\n📦 [Step 1] Surfaced ${rawCrashes.length} raw crash logs from Android build.`);

  // 2. Parse and collect structured crash details
  const parsedCrashes = CrashCollector.processAll(rawCrashes);
  console.log(`📋 [Step 2] Extracted ${parsedCrashes.length} unique Crash IDs and backtraces.`);

  // 3. Classify with Gemini using the ASB reference dataset & perform Root Cause Analysis
  const classifier = new GeminiCrashClassifier();
  const classifiedResults = [];

  console.log(`\n🧠 [Step 3] Running Gemini Reference-Set Classification & Root Cause Analysis...`);
  for (const crash of parsedCrashes) {
    const analyzed = await classifier.analyzeCrash(crash);
    classifiedResults.push(analyzed);
    console.log(`   ✓ [${analyzed.crash_id}] ${analyzed.components} | ${analyzed.severity.toUpperCase()} | ${analyzed.type}`);
  }

  // 4. Publish results to the Bulletin Board
  console.log(`\n📤 [Step 4] Publishing results to Security Bulletin Board...`);
  let publishedCount = 0;

  for (const bug of classifiedResults) {
    try {
      // Attempt HTTP POST to Express API if running
      await axios.post(apiUrl, bug, { timeout: 2000 });
      publishedCount++;
      console.log(`   📡 Published ${bug.crash_id} to ${apiUrl}`);
    } catch (err) {
      // If server is not running, persist directly to dataset files
      directPersist(bug, outputPath);
      directPersist(bug, frontendDataPath);
      publishedCount++;
      console.log(`   💾 Direct persisted ${bug.crash_id} to dataset files (${err.message})`);
    }
  }

  console.log("\n==================================================================");
  console.log(`🎉 PIPELINE COMPLETE: ${publishedCount} newly surfaced fuzzer bugs analyzed & published!`);
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

    // Check if ID already exists
    const idx = existing.findIndex(e => (e.cve_id === item.cve_id || e.crash_id === item.cve_id));
    if (idx >= 0) {
      existing[idx] = item;
    } else {
      existing.unshift(item); // Add to top
    }

    fs.writeFileSync(filePath, JSON.stringify(existing, null, 2));
  } catch (err) {
    console.error(`Failed to persist directly to ${filePath}:`, err.message);
  }
}

// CLI Execution
if (process.argv[1] && process.argv[1].endsWith("pipeline.js")) {
  runFuzzingAndPublishPipeline({ iterations: 4 });
}
