#!/usr/bin/env node
/**
 * One-off migration: re-run Gemini on every ASB record whose summary is a
 * failure message ("Error generating summary." / "Error ...").
 *
 * Records that still fail are marked `summary_status: "failed"` instead of
 * leaving a failure message masquerading as content. Records that succeed get
 * a real summary and `summary_status: "ok"`.
 *
 * Requires GEMINI_API_KEY. Run from the repo root:
 *   node scripts/repair_failed_summaries.js [path-to-dataset.json]
 */
import { GoogleGenAI } from "@google/genai";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DATASET = path.resolve(__dirname, "..", "SumPatches_output.json");
const OSV_API_URL = "https://api.osv.dev/v1/vulns/";

const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
  console.error("GEMINI_API_KEY is not set. Cannot repair summaries without Gemini.");
  process.exit(1);
}

const genai = new GoogleGenAI({ apiKey });
const MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

function isFailedSummary(summary) {
  return typeof summary === "string" && /^Error\b/.test(summary.trim());
}

async function fetchOsvDetails(osvId) {
  try {
    const { data } = await axios.get(`${OSV_API_URL}${osvId}`);
    return data;
  } catch (err) {
    console.warn(`  OSV fetch failed for ${osvId}: ${err.message}`);
    return null;
  }
}

async function summarizeWithGemini(osvDetails) {
  const prompt = `Analyze and summarize this Android security vulnerability in clear, non-technical terms suitable for a security bulletin. Return a plain-text summary (no markdown, no JSON):\n\n${JSON.stringify(osvDetails, null, 2)}`;
  const response = await genai.models.generateContent({
    model: MODEL,
    contents: prompt,
  });
  const text = response.text;
  if (!text) throw new Error("Empty Gemini response");
  return text.trim();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const datasetPath = process.argv[2] || DEFAULT_DATASET;
  if (!fs.existsSync(datasetPath)) {
    console.error(`Dataset not found: ${datasetPath}`);
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(datasetPath, "utf-8"));
  const failed = data.filter(r => r.source === "asb" && isFailedSummary(r.summary));
  console.log(`Found ${failed.length} ASB records with failed summaries.`);

  let ok = 0;
  let stillFailed = 0;
  let requestCount = 0;

  for (const record of failed) {
    const id = record.cve_id || record.asb_id;
    console.log(`\nProcessing ${id}...`);

    const osvDetails = await fetchOsvDetails(id);
    if (!osvDetails) {
      record.summary_status = "failed";
      record.summary_error = "OSV details unavailable";
      stillFailed++;
      continue;
    }

    try {
      const summary = await summarizeWithGemini(osvDetails);
      record.summary = summary;
      record.summary_status = "ok";
      record.modelVersion = MODEL;
      record.model_version = MODEL;
      ok++;
      console.log(`  ✓ summary regenerated (${summary.length} chars)`);
    } catch (err) {
      record.summary_status = "failed";
      record.summary_error = err.message;
      stillFailed++;
      console.warn(`  ✗ ${err.message}`);
    }

    requestCount++;
    if (requestCount > 1 && requestCount % 15 === 0) {
      console.log("15 requests made. Sleeping for 1 minute...");
      await sleep(61000);
    }
  }

  fs.writeFileSync(datasetPath, JSON.stringify(data, null, 2));
  console.log(`\nDone. ${ok} repaired, ${stillFailed} marked failed. Wrote ${datasetPath}`);
}

main().catch(err => {
  console.error("Migration failed:", err.message);
  process.exit(1);
});
