import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { fetchJsonData, processVulnerabilities } from "./SumPatches.js";

dotenv.config();

const app = express();
const PORT = 20000;

app.use(cors());
app.use(express.json());

// Define the vulnerability data structure
const vulnerabilityData = {
  framework: [
    { cve: "CVE-2025-001", references: "https://example.com", type: "EoP", severity: "High", versions: "12, 13" },
    { cve: "CVE-2025-002", references: "https://example.com", type: "ID", severity: "Medium", versions: "12" },
  ],
  kernel: [
    { cve: "CVE-2025-003", references: "https://example.com", type: "DoS", severity: "Low", versions: "11, 12" },
  ],
  "arm-components": [],
};

// Fetch vulnerabilities for a specific section
app.get("/api/sections/:section", (req, res) => {
  const section = req.params.section;
  const sectionVulnerabilities = vulnerabilityData[section];

  if (sectionVulnerabilities) {
    res.json(sectionVulnerabilities);
  } else {
    res.status(404).json({ message: "Section not found" });
  }
});

// Existing endpoint for fetching and processing vulnerability data from the external JSON URL
const jsonUrl = "https://storage.googleapis.com/osv-android-api/v1/android_sdk_34.json";

app.get("/api/vulnerabilities", async (req, res) => {
  try {
    console.log("Fetching JSON data...");
    const jsonData = await fetchJsonData(jsonUrl);

    console.log("Processing vulnerabilities...");
    const processedVulnerabilities = await processVulnerabilities(jsonData);

    res.json(processedVulnerabilities);
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).json({ error: "Failed to fetch vulnerabilities" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
