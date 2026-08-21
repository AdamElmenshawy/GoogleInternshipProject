import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

/**
 * Gemini LLM Crash Root-Cause Analyzer & ASB Reference Classifier.
 *
 * Uses the current @google/genai SDK with structured output (responseSchema).
 * There is NO heuristic fallback: if Gemini is unavailable or returns output
 * that fails schema validation, the crash is queued for retry and the error is
 * propagated — it is never silently accepted and never silently discarded.
 */

/**
 * Structured-output schema enforced on every Gemini analysis response.
 * These are the exact fields the dashboard and VRP reporter consume.
 */
export const CRASH_ANALYSIS_SCHEMA = {
  type: "OBJECT",
  properties: {
    component: {
      type: "STRING",
      description: "Affected Android component: Framework, Kernel, Vendor, Media / Codec, System Server, or Graphics",
    },
    vulnerability_type: {
      type: "STRING",
      enum: ["EoP", "DoS", "ID", "Memory Corruption", "RCE"],
      description: "Elevation of Privilege, Denial of Service, Information Disclosure, Memory Corruption, or Remote Code Execution",
    },
    severity: {
      type: "STRING",
      enum: ["critical", "high", "medium", "low"],
    },
    confidence: {
      type: "NUMBER",
      description: "0.0 to 1.0 confidence in this classification",
    },
    root_cause_hypothesis: {
      type: "STRING",
      description: "Clear, readable non-technical explanation of the root cause and security impact",
    },
    supporting_frames: {
      type: "ARRAY",
      items: { type: "STRING" },
      description: "Backtrace frames that support the root-cause hypothesis",
    },
    reference_ids: {
      type: "ARRAY",
      items: { type: "STRING" },
      description: "Matching ASB/CVE reference IDs from the reference set, if any",
    },
    missing_evidence: {
      type: "ARRAY",
      items: { type: "STRING" },
      description: "Evidence still needed to confirm the hypothesis (e.g. minimized reproducer, exact build)",
    },
  },
  required: [
    "component",
    "vulnerability_type",
    "severity",
    "confidence",
    "root_cause_hypothesis",
    "supporting_frames",
    "reference_ids",
    "missing_evidence",
  ],
};

const VALID_TYPES = new Set(["EoP", "DoS", "ID", "Memory Corruption", "RCE"]);
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);

/**
 * True only for genuine ASB/OSV bulletin identifiers.
 */
export function isValidAsbId(id) {
  if (!id) return false;
  return /^(ASB-A-|PUB-A-|CVE-)/.test(id);
}

/**
 * Best-effort component hint derived from the crashing process name, used to
 * select relevant reference examples before Gemini classifies.
 */
export function guessComponent(processName) {
  const p = (processName || "").toLowerCase();
  if (p.includes("netd") || p.includes("kernel")) return "kernel";
  if (p.includes("bluetooth") || p.includes("qti") || p.includes("vendor")) return "vendor";
  if (p.includes("media") || p.includes("codec") || p.includes("hevc") || p.includes("webp")) return "media";
  if (p.includes("surfaceflinger") || p.includes("system_server")) return "framework";
  return "";
}

/**
 * Validates a parsed Gemini response against the schema contract.
 */
export function validateAnalysis(analysis) {
  if (!analysis || typeof analysis !== "object") return false;
  if (!analysis.component || typeof analysis.component !== "string") return false;
  if (!VALID_TYPES.has(analysis.vulnerability_type)) return false;
  if (!VALID_SEVERITIES.has((analysis.severity || "").toLowerCase())) return false;
  if (typeof analysis.confidence !== "number" || analysis.confidence < 0 || analysis.confidence > 1) return false;
  if (!analysis.root_cause_hypothesis || typeof analysis.root_cause_hypothesis !== "string") return false;
  if (!Array.isArray(analysis.supporting_frames)) return false;
  if (!Array.isArray(analysis.reference_ids)) return false;
  if (!Array.isArray(analysis.missing_evidence)) return false;
  return true;
}

export class GeminiCrashClassifier {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.GEMINI_API_KEY;
    this.modelName = options.modelName || "gemini-2.5-flash";
    this.referenceDataPath = options.referenceDataPath || path.resolve("SumPatches_output.json");
    this.fallbackDataPath = path.resolve("asb-app/src/data/SumPatches_output.json");
    // Crashes whose Gemini response failed validation land here for retry.
    this.pendingRetryQueue = [];

    if (!this.apiKey) {
      throw new Error(
        "GEMINI_API_KEY not set. Analysis cannot proceed without Gemini. " +
        "Set GEMINI_API_KEY in the environment or .env file."
      );
    }
    this.genai = new GoogleGenAI({ apiKey: this.apiKey });
  }

  /**
   * Loads labeled ASB reference examples for a component.
   *
   * STRICT FILTER: only records that are (a) source === 'asb', (b) carry a
   * real bulletin ID, and (c) have a real (non-"Error") summary may be used as
   * reference examples. Fuzzer findings are NEVER reference examples — a
   * fabricated crash must not become ground truth for classifying real ones.
   */
  loadReferenceExamples(component) {
    let filePath = fs.existsSync(this.referenceDataPath) ? this.referenceDataPath : this.fallbackDataPath;
    if (!fs.existsSync(filePath)) {
      return [];
    }

    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      const componentKey = (component || "").toLowerCase();

      return data
        .filter(r =>
          r.source === "asb" &&
          r.summary &&
          !r.summary.startsWith("Error") &&
          isValidAsbId(r.cve_id || r.asb_id) &&
          (!componentKey || (r.components || "").toLowerCase().includes(componentKey))
        )
        .slice(0, 5); // 5 examples max — more dilutes the prompt
    } catch (err) {
      console.warn("Could not read ASB reference dataset:", err.message);
      return [];
    }
  }

  /**
   * Constructs the structured prompt with few-shot labeled reference examples.
   */
  buildPrompt(crashReport, referenceExamples) {
    const referenceText = referenceExamples.map((ex, i) => `
[Reference ASB Example #${i + 1}]
CVE/Identifier: ${ex.cve_id}
Component: ${ex.components}
Severity: ${ex.severity}
Description & Summary: ${ex.summary}
`).join("\n");

    return `
You are a top-tier Android Security & Exploit Analysis Engine.
You are analyzing a newly surfaced crash discovered by an Android Fuzzer running on modern Android builds (Android 14/15, API 34/35).

### TASK:
1. Compare this newly found crash against the labeled Android Security Bulletin (ASB) reference dataset below.
2. Classify the crash into a component, vulnerability type, and severity.
3. Perform Root-Cause Analysis: explain the exact root cause in clear, readable non-technical terms suitable for security bulletin reporting.
4. List the backtrace frames that support your hypothesis, any matching ASB/CVE reference IDs, and what evidence is still missing.

### LABELED ASB REFERENCE DATASET EXAMPLES:
${referenceText || "(no reference examples available for this component)"}

### NEW FUZZER CRASH TO ANALYZE:
Process: ${crashReport.process}
Sanitizer / Fault Type: ${crashReport.sanitizer || crashReport.signal}
Signal & Code: ${crashReport.signal}${crashReport.signal_code ? ` (code ${crashReport.signal_code})` : ""}
Fault Address: ${crashReport.fault_address}
Cause: ${crashReport.cause}
Backtrace:
${crashReport.backtrace}
${crashReport.reproducer_hex ? `Reproducer Hex: ${crashReport.reproducer_hex}` : ""}

### OUTPUT FORMAT:
Return ONLY valid JSON matching the provided schema. No markdown, no commentary.
`;
  }

  /**
   * Calls Gemini with structured output. Throws on any failure — the caller
   * decides whether to retry. Never falls back to a heuristic.
   */
  async analyzeWithGemini(crashReport, referenceExamples) {
    const response = await this.genai.models.generateContent({
      model: this.modelName,
      contents: this.buildPrompt(crashReport, referenceExamples),
      config: {
        responseMimeType: "application/json",
        responseSchema: CRASH_ANALYSIS_SCHEMA,
      },
    });

    const text = response.text;
    if (!text) {
      throw new Error("Gemini returned an empty response");
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new Error(`Gemini returned non-JSON output: ${err.message}`);
    }

    if (!validateAnalysis(parsed)) {
      this.pendingRetryQueue.push(crashReport.crash_id);
      throw new Error(`Gemini response failed schema validation for ${crashReport.crash_id}`);
    }

    return parsed;
  }

  /**
   * Analyzes and classifies a crash report using Gemini.
   * Throws on failure (no silent fallback); the pipeline queues for retry.
   */
  async analyzeCrash(crashReport) {
    const componentHint = crashReport.component || guessComponent(crashReport.process);
    const referenceExamples = this.loadReferenceExamples(componentHint);

    console.log(`[Gemini Classifier] Analyzing ${crashReport.crash_id} with ${this.modelName}...`);
    const analysis = await this.analyzeWithGemini(crashReport, referenceExamples);
    return this.formatOutput(crashReport, analysis, this.modelName);
  }

  /**
   * Formats the final unified record. Keeps legacy display fields for the
   * dashboard while adding the schema fields the VRP reporter consumes.
   */
  formatOutput(crashReport, analysis, modelVersion) {
    const severity = (analysis.severity || "high").toLowerCase();
    return {
      crash_id: crashReport.crash_id,
      cve_id: crashReport.crash_id,
      source: crashReport.source || "fuzzer",
      status: "analyzed",
      process: crashReport.process,
      process_name: crashReport.process_name || crashReport.process,
      component: analysis.component,
      components: analysis.component, // legacy dashboard field
      vulnerability_type: analysis.vulnerability_type,
      type: analysis.vulnerability_type, // legacy dashboard field
      severity,
      confidence: analysis.confidence,
      root_cause_hypothesis: analysis.root_cause_hypothesis,
      summary: analysis.root_cause_hypothesis, // legacy dashboard field
      supporting_frames: analysis.supporting_frames,
      reference_ids: analysis.reference_ids,
      missing_evidence: analysis.missing_evidence,
      signal: crashReport.signal,
      signal_code: crashReport.signal_code,
      fault_address: crashReport.fault_address,
      cause: crashReport.cause,
      backtrace: crashReport.backtrace,
      stack_trace: crashReport.backtrace, // legacy dashboard field
      raw_log: crashReport.raw_log,
      target_build: crashReport.target_build || "Android 15 (VanillaIceCream - API 35)",
      sanitizer: crashReport.sanitizer || "HWASan",
      reproducer_hex: crashReport.reproducer_hex || null,
      reproducer_path: crashReport.reproducer_path || null,
      date: crashReport.date || new Date().toISOString().split("T")[0],
      model_version: modelVersion,
      modelVersion, // legacy dashboard field
      simulated: crashReport.simulated || false,
    };
  }
}
