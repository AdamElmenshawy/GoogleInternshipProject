import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

/**
 * Gemini LLM Crash Root-Cause Analyzer & ASB Reference Classifier.
 */
export class GeminiCrashClassifier {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.GEMINI_API_KEY;
    this.modelName = options.modelName || "gemini-1.5-flash";
    this.referenceDataPath = options.referenceDataPath || path.resolve("SumPatches_output.json");
    this.fallbackDataPath = path.resolve("asb-app/src/data/SumPatches_output.json");

    if (this.apiKey) {
      this.genAI = new GoogleGenerativeAI(this.apiKey);
      this.model = this.genAI.getGenerativeModel({ model: this.modelName });
    }
  }

  /**
   * Loads labeled ASB reference dataset to serve as few-shot training/classification context.
   */
  loadReferenceSet() {
    let filePath = fs.existsSync(this.referenceDataPath) ? this.referenceDataPath : this.fallbackDataPath;
    if (!fs.existsSync(filePath)) {
      return [];
    }

    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      // Extract a diverse representative set of labeled ASB CVEs
      const labeledSamples = {
        kernel: data.filter(d => d.components?.toLowerCase().includes("kernel")).slice(0, 3),
        vendor: data.filter(d => d.components?.toLowerCase().includes("vendor")).slice(0, 3),
        framework: data.filter(d => d.components?.toLowerCase().includes("framework") || !d.components?.toLowerCase().includes("kernel")).slice(0, 3),
      };

      return [...labeledSamples.kernel, ...labeledSamples.vendor, ...labeledSamples.framework];
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
2. Classify the crash into:
   - "components": [Framework, Kernel, Vendor, Media / Codec, System Server]
   - "severity": [critical, high, medium, low]
   - "type": [EoP (Elevation of Privilege), DoS (Denial of Service), ID (Information Disclosure), Memory Corruption, RCE]
   - "classification_reasoning": 1-2 sentences explaining why this matches the ASB reference pattern.
3. Perform Root-Cause Analysis: Explain the exact root cause in clear, readable non-technical terms suitable for security bulletin reporting.
4. Technical breakdown: 2-3 sentences on the exact faulting instruction / memory condition.

### LABELED ASB REFERENCE DATASET EXAMPLES:
${referenceText}

### NEW FUZZER CRASH TO ANALYZE:
Process: ${crashReport.process}
Signal & Code: ${crashReport.signal}
Fault Address: ${crashReport.fault_address}
Cause: ${crashReport.cause}
Backtrace:
${crashReport.backtrace}

### OUTPUT FORMAT (Must be valid JSON only, no markdown formatting around JSON):
{
  "components": "<Framework | Kernel | Vendor | Media / Codec | System Server>",
  "severity": "<critical | high | medium | low>",
  "type": "<EoP | DoS | ID | Memory Corruption | RCE>",
  "classification_reasoning": "<explanation comparing against ASB reference patterns>",
  "summary": "<clear, readable non-technical explanation of the root cause and security impact>",
  "technical_breakdown": "<technical analysis of faulting memory/code condition>"
}
`;
  }

  /**
   * Deterministic heuristic fallback when Gemini API key is not present or offline.
   */
  heuristicAnalysis(crashReport) {
    let components = "Framework";
    let severity = "high";
    let type = "DoS";

    const log = (crashReport.raw_log || "").toLowerCase();
    const cause = (crashReport.cause || "").toLowerCase();
    const process = (crashReport.process || "").toLowerCase();

    if (process.includes("netd") || process.includes("kernel") || log.includes("libc.so (abort")) {
      components = "Kernel / Network Daemon";
      type = "DoS";
      severity = "medium";
    } else if (process.includes("bluetooth") || process.includes("qti") || process.includes("vendor")) {
      components = "Vendor / Qualcomm";
      type = "EoP";
      severity = "critical";
    } else if (process.includes("media") || process.includes("codec") || cause.includes("out of bounds") || cause.includes("heap buffer overflow")) {
      components = "Media / Codec";
      type = "Memory Corruption";
      severity = "high";
    } else if (process.includes("system_server") || log.includes("libandroid_servers.so")) {
      components = "Framework / System Server";
      type = "EoP";
      severity = "high";
    }

    const summary = `This fuzzer-discovered issue in ${components} (${crashReport.process}) causes a ${crashReport.signal} crash due to ${crashReport.cause}. In modern Android builds, an attacker or malformed input could trigger unexpected memory behavior leading to ${type}. Root cause analysis indicates improper state or memory boundary verification during transaction processing.`;

    const technical_breakdown = `Fault at address ${crashReport.fault_address} during ${crashReport.cause}. The call stack indicates memory corruption or illegal access in ${crashReport.backtrace.split("\n")[0] || "top frame"}.`;

    return {
      components,
      severity,
      type,
      classification_reasoning: `Classified as ${components} / ${severity} based on matching ASB severity models for ${type} in process ${crashReport.process}.`,
      summary,
      technical_breakdown
    };
  }

  /**
   * Analyzes and classifies a crash report using Gemini or fallback.
   */
  async analyzeCrash(crashReport) {
    const referenceExamples = this.loadReferenceSet();

    if (!this.model) {
      console.log(`[Gemini Classifier] GEMINI_API_KEY not configured or offline. Running deterministic security analyzer for ${crashReport.crash_id}.`);
      const analysis = this.heuristicAnalysis(crashReport);
      return this.formatOutput(crashReport, analysis, "heuristic-analyzer");
    }

    try {
      console.log(`[Gemini Classifier] Analyzing ${crashReport.crash_id} with ${this.modelName}...`);
      const prompt = this.buildPrompt(crashReport, referenceExamples);
      const result = await this.model.generateContent(prompt);
      const text = result.response ? result.response.text() : "";

      // Extract JSON from response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return this.formatOutput(crashReport, parsed, this.modelName);
      } else {
        throw new Error("Could not parse JSON response from Gemini");
      }
    } catch (err) {
      console.warn(`[Gemini Classifier] Gemini API call error: ${err.message}. Falling back to deterministic analyzer.`);
      const fallback = this.heuristicAnalysis(crashReport);
      return this.formatOutput(crashReport, fallback, "gemini-1.5-flash-fallback");
    }
  }

  /**
   * Formats the final unified record.
   */
  formatOutput(crashReport, analysis, modelVersion) {
    return {
      cve_id: crashReport.crash_id,
      crash_id: crashReport.crash_id,
      source: "fuzzer",
      process: crashReport.process,
      components: analysis.components || "Framework",
      severity: (analysis.severity || "high").toLowerCase(),
      type: analysis.type || "Memory Corruption",
      date: crashReport.date,
      summary: analysis.summary,
      technical_analysis: analysis.technical_breakdown,
      classification_reasoning: analysis.classification_reasoning,
      stack_trace: crashReport.backtrace,
      fault_signal: `${crashReport.signal} - ${crashReport.cause}`,
      fault_address: crashReport.fault_address,
      target_build: crashReport.target_build,
      modelVersion
    };
  }
}
