import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { runFuzzingAndPublishPipeline } from "./fuzzer/pipeline.js";
import {
  CRASH_STATUS_FLOW,
  VALID_CRASH_STATUSES,
  isValidTransition,
} from "./fuzzer/status_machine.js";

// Re-export for consumers (e.g. tests) that import from server.js directly.
export { CRASH_STATUS_FLOW, VALID_CRASH_STATUSES };

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 20000;

// Locked-down CORS: only the local dashboard may call this API.
const ALLOWED_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:3000";
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: "10mb" }));

const rootOutputFile = path.join(__dirname, "SumPatches_output.json");
const frontendOutputFile = path.join(__dirname, "asb-app", "src", "data", "SumPatches_output.json");

/**
 * Middleware: require a valid ingest API key on write endpoints.
 * The key is read from the `x-api-key` header and compared against
 * INGEST_API_KEY. If INGEST_API_KEY is unset, writes are refused outright
 * (fail-closed) rather than silently allowed.
 */
function requireApiKey(req, res, next) {
  const expected = process.env.INGEST_API_KEY;
  if (!expected) {
    return res.status(503).json({
      error: "INGEST_API_KEY is not configured on the server. Refusing write.",
    });
  }
  const provided = req.headers["x-api-key"];
  if (!provided || provided !== expected) {
    return res.status(401).json({ error: "Unauthorized: missing or invalid x-api-key" });
  }
  next();
}

/**
 * Helper to read dataset from disk
 */
function readDataset() {
  const targetPath = fs.existsSync(rootOutputFile) ? rootOutputFile : frontendOutputFile;
  if (!fs.existsSync(targetPath)) {
    return [];
  }
  try {
    const data = fs.readFileSync(targetPath, "utf-8").trim();
    return data ? JSON.parse(data) : [];
  } catch (err) {
    console.error("Error reading dataset:", err.message);
    return [];
  }
}

/**
 * Helper to write dataset to both root and frontend paths
 */
function writeDataset(dataset) {
  const jsonStr = JSON.stringify(dataset, null, 2);
  fs.writeFileSync(rootOutputFile, jsonStr);
  if (fs.existsSync(path.dirname(frontendOutputFile))) {
    fs.writeFileSync(frontendOutputFile, jsonStr);
  }
}

// GET /api/vulnerabilities - published findings only, with filtering support
app.get("/api/vulnerabilities", (req, res) => {
  try {
    let vulnerabilities = readDataset();
    const { source, month, severity, component, limit, status } = req.query;

    // Findings endpoint: by default only show published records.
    // Pass ?status=all to include every state (used by the review dashboard).
    if (status && status !== "all") {
      vulnerabilities = vulnerabilities.filter(item => item.status === status);
    } else if (!status) {
      vulnerabilities = vulnerabilities.filter(item => item.status === "published");
    }

    // Filter by source (asb vs fuzzer vs all)
    if (source && source !== "all") {
      vulnerabilities = vulnerabilities.filter(item => {
        if (source === "fuzzer") {
          return item.source === "fuzzer" || (item.cve_id && item.cve_id.startsWith("CRASH-"));
        } else if (source === "asb") {
          return item.source === "asb" || (!item.source && !item.cve_id?.startsWith("CRASH-"));
        }
        return true;
      });
    }

    // Filter by month (YYYY-MM)
    if (month) {
      const [year, m] = month.split("-");
      vulnerabilities = vulnerabilities.filter(item => {
        if (!item.date) return false;
        const itemDate = new Date(item.date);
        return itemDate.getFullYear() === parseInt(year) && (itemDate.getMonth() + 1) === parseInt(m);
      });
    }

    // Filter by severity
    if (severity) {
      vulnerabilities = vulnerabilities.filter(item =>
        item.severity && item.severity.toLowerCase() === severity.toLowerCase()
      );
    }

    // Filter by component
    if (component) {
      vulnerabilities = vulnerabilities.filter(item =>
        item.components && item.components.toLowerCase().includes(component.toLowerCase())
      );
    }

    if (limit) {
      vulnerabilities = vulnerabilities.slice(0, parseInt(limit));
    }

    res.json(vulnerabilities);
  } catch (error) {
    console.error("Error retrieving vulnerabilities:", error.message);
    res.status(500).json({ error: "Failed to retrieve vulnerabilities data" });
  }
});

// GET /api/crashes - review queue (pending_review, ingested, analyzed, rejected)
app.get("/api/crashes", (req, res) => {
  try {
    const { status } = req.query;
    let crashes = readDataset().filter(item => item.source === "fuzzer" || item.cve_id?.startsWith("CRASH-"));
    if (status && status !== "all") {
      crashes = crashes.filter(item => item.status === status);
    }
    res.json(crashes);
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve crash records" });
  }
});

// GET /api/stats - summary metrics for dashboard
app.get("/api/stats", (req, res) => {
  try {
    const dataset = readDataset();
    const fuzzerCrashes = dataset.filter(d => d.source === "fuzzer" || d.cve_id?.startsWith("CRASH-"));
    const asbCVEs = dataset.filter(d => d.source !== "fuzzer" && !d.cve_id?.startsWith("CRASH-"));

    const severityCounts = dataset.reduce((acc, item) => {
      const s = (item.severity || "unknown").toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});

    const statusCounts = dataset.reduce((acc, item) => {
      const st = item.status || "unknown";
      acc[st] = (acc[st] || 0) + 1;
      return acc;
    }, {});

    res.json({
      total: dataset.length,
      asbCount: asbCVEs.length,
      fuzzerCount: fuzzerCrashes.length,
      severities: severityCounts,
      statuses: statusCounts,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to calculate stats" });
  }
});

// POST /api/crashes (and /api/vulnerabilities) - Ingest a newly discovered/classified bug.
// Requires x-api-key. New records enter the lifecycle at `ingested`.
app.post(["/api/vulnerabilities", "/api/crashes"], requireApiKey, (req, res) => {
  try {
    const newBug = req.body;
    if (!newBug || (!newBug.cve_id && !newBug.crash_id)) {
      return res.status(400).json({ error: "Invalid payload: cve_id or crash_id is required" });
    }

    const id = newBug.cve_id || newBug.crash_id;
    newBug.cve_id = id;
    if (!newBug.date) {
      newBug.date = new Date().toISOString().split("T")[0];
    }

    // Enforce the state machine on ingest.
    const requestedStatus = newBug.status;
    if (requestedStatus && !VALID_CRASH_STATUSES.has(requestedStatus)) {
      return res.status(400).json({ error: `Invalid status: ${requestedStatus}` });
    }

    const dataset = readDataset();
    const existingIndex = dataset.findIndex(item => item.cve_id === id);

    if (existingIndex >= 0) {
      const current = dataset[existingIndex];
      const next = requestedStatus || current.status || "ingested";
      if (!isValidTransition(current.status || "ingested", next)) {
        return res.status(409).json({
          error: `Illegal status transition: ${current.status || "ingested"} -> ${next}`,
        });
      }
      dataset[existingIndex] = { ...current, ...newBug, status: next };
      console.log(`[API] Updated existing record: ${id} (status: ${next})`);
    } else {
      newBug.status = requestedStatus || "ingested";
      dataset.unshift(newBug);
      console.log(`[API] Ingested new record: ${id} (status: ${newBug.status})`);
    }

    writeDataset(dataset);
    res.status(201).json({ success: true, message: `Successfully ingested ${id}`, bug: newBug });
  } catch (error) {
    console.error("Error publishing bug:", error.message);
    res.status(500).json({ error: "Failed to save vulnerability record" });
  }
});

// POST /api/crashes/:id/publish - Human approval gate. Moves a crash to `published`.
app.post("/api/crashes/:id/publish", requireApiKey, (req, res) => {
  try {
    const id = req.params.id;
    const dataset = readDataset();
    const idx = dataset.findIndex(item => item.cve_id === id || item.crash_id === id);
    if (idx === -1) {
      return res.status(404).json({ error: `No record found for ${id}` });
    }
    const current = dataset[idx];
    if (!isValidTransition(current.status || "ingested", "published")) {
      return res.status(409).json({
        error: `Cannot publish from status ${current.status || "ingested"}`,
      });
    }
    dataset[idx] = { ...current, status: "published", published_at: new Date().toISOString() };
    writeDataset(dataset);
    res.json({ success: true, message: `Published ${id}`, bug: dataset[idx] });
  } catch (error) {
    res.status(500).json({ error: "Failed to publish record" });
  }
});

// POST /api/crashes/:id/reject - Human decision to drop a crash from the pipeline.
app.post("/api/crashes/:id/reject", requireApiKey, (req, res) => {
  try {
    const id = req.params.id;
    const dataset = readDataset();
    const idx = dataset.findIndex(item => item.cve_id === id || item.crash_id === id);
    if (idx === -1) {
      return res.status(404).json({ error: `No record found for ${id}` });
    }
    const current = dataset[idx];
    if (current.status === "published") {
      return res.status(409).json({ error: "Published records cannot be rejected" });
    }
    dataset[idx] = { ...current, status: "rejected", rejected_at: new Date().toISOString() };
    writeDataset(dataset);
    res.json({ success: true, message: `Rejected ${id}`, bug: dataset[idx] });
  } catch (error) {
    res.status(500).json({ error: "Failed to reject record" });
  }
});

// POST /api/fuzzer/trigger - Run fuzzer & classification pipeline on demand.
// Requires x-api-key. Defaults to device mode; simulation must be explicit.
app.post("/api/fuzzer/trigger", requireApiKey, async (req, res) => {
  try {
    const { iterations = 2, mode } = req.body;
    const resolvedMode = mode || process.env.FUZZER_MODE || "device";
    console.log(`[API] Triggering Fuzzer Campaign (iterations: ${iterations}, mode: ${resolvedMode})`);

    // Run pipeline asynchronously
    runFuzzingAndPublishPipeline({ iterations, mode: resolvedMode }).catch(err => {
      console.error("[Pipeline Error]", err);
    });

    res.json({ success: true, message: `Fuzzer campaign launched with ${iterations} iterations in ${resolvedMode} mode.` });
  } catch (error) {
    res.status(500).json({ error: "Failed to launch fuzzer pipeline" });
  }
});

app.listen(PORT, () => {
  console.log(`Android Security Bulletin & Fuzzer API running on port ${PORT}`);
  if (!process.env.INGEST_API_KEY) {
    console.warn("WARNING: INGEST_API_KEY is not set. All write endpoints will refuse requests (fail-closed).");
  }
});
