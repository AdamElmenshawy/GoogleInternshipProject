import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { runFuzzingAndPublishPipeline } from "./fuzzer/pipeline.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 20000;

app.use(cors());
app.use(express.json({ limit: "10mb" }));

const rootOutputFile = path.join(__dirname, "SumPatches_output.json");
const frontendOutputFile = path.join(__dirname, "asb-app", "src", "data", "SumPatches_output.json");

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

// GET /api/vulnerabilities - with filtering support
app.get("/api/vulnerabilities", (req, res) => {
  try {
    let vulnerabilities = readDataset();
    const { source, month, severity, component, limit } = req.query;

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

    res.json({
      total: dataset.length,
      asbCount: asbCVEs.length,
      fuzzerCount: fuzzerCrashes.length,
      severities: severityCounts
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to calculate stats" });
  }
});

// POST /api/vulnerabilities (and /api/crashes) - Publish newly discovered/classified bug
app.post(["/api/vulnerabilities", "/api/crashes"], (req, res) => {
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

    const dataset = readDataset();
    const existingIndex = dataset.findIndex(item => item.cve_id === id);

    if (existingIndex >= 0) {
      dataset[existingIndex] = { ...dataset[existingIndex], ...newBug };
      console.log(`[API] Updated existing record: ${id}`);
    } else {
      dataset.unshift(newBug);
      console.log(`[API] Published new record: ${id} (${newBug.source || "asb"})`);
    }

    writeDataset(dataset);
    res.status(201).json({ success: true, message: `Successfully published ${id}`, bug: newBug });
  } catch (error) {
    console.error("Error publishing bug:", error.message);
    res.status(500).json({ error: "Failed to save vulnerability record" });
  }
});

// POST /api/fuzzer/trigger - Run fuzzer & classification pipeline on demand
app.post("/api/fuzzer/trigger", async (req, res) => {
  try {
    const { iterations = 2, mode = "simulation" } = req.body;
    console.log(`[API] Triggering Fuzzer Campaign (iterations: ${iterations}, mode: ${mode})`);
    
    // Run pipeline asynchronously
    runFuzzingAndPublishPipeline({ iterations, mode }).catch(err => {
      console.error("[Pipeline Error]", err);
    });

    res.json({ success: true, message: `Fuzzer campaign launched with ${iterations} iterations in ${mode} mode.` });
  } catch (error) {
    res.status(500).json({ error: "Failed to launch fuzzer pipeline" });
  }
});

app.listen(PORT, () => {
  console.log(`Android Security Bulletin & Fuzzer API running on port ${PORT}`);
});
