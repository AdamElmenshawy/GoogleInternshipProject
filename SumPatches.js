import { GoogleGenerativeAI } from "@google/generative-ai";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

const OSV_API_URL = "https://api.osv.dev/v1/vulns/";
const geminiApiKey = process.env.GEMINI_API_KEY;

if (!geminiApiKey) {
    throw new Error("Gemini API Key is missing. Please set GEMINI_API_KEY in your environment.");
}

const genAI = new GoogleGenerativeAI(geminiApiKey);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

export async function fetchJsonData(url) {
    try {
        const response = await axios.get(url);
        return response.data;
    } catch (error) {
        console.error("Error fetching JSON data:", error.message);
        throw error;
    }
}

export function extractVulnerabilities(data) {
    const vulnerabilities = [];
    for (const date in data.vulnerabilities) {
        const patchesForDate = data.vulnerabilities[date];
        patchesForDate.forEach((vuln) => {
            const identifiers = vuln.asb_identifiers || [];
            identifiers.forEach((id) => {
                vulnerabilities.push({
                    cve_id: id,
                    description: vuln.description || "No description available",
                    severity: vuln.severity || "Unknown severity",
                    components: vuln.components ? vuln.components.join(", ") : "No components available",
                    date,
                });
            });
        });
    }
    return vulnerabilities;
}

export async function fetchOSVDetails(osvId) {
    try {
        const response = await axios.get(`${OSV_API_URL}${osvId}`);
        return response.data;
    } catch (error) {
        console.error(`Error fetching details for OSV ID ${osvId}:`, error.message);
        return null;
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function processWithGemini(osvDetails) {
    try {
        const prompt = `Analyze and summarize this security vulnerability in clear, non-technical terms:\n\n${JSON.stringify(osvDetails, null, 2)}`;
        const result = await model.generateContent(prompt);

        console.log("Gemini API Response:", JSON.stringify(result, null, 2));

        const summary = result.response ? result.response.text() : "No summary returned";

        console.log("Generated Summary:", summary);

        return summary;
    } catch (error) {
        console.error("Error processing data with Gemini AI:", error.message);
        return "Error generating summary.";
    }
}

function readExistingVulnerabilities(filename) {
    if (!fs.existsSync(filename)) {
        return new Set();
    }
    try {
        const data = fs.readFileSync(filename, "utf-8").trim();
        if (!data || data === "[]") {
            return new Set();
        }
        const vulnerabilities = JSON.parse(data);
        return new Set(vulnerabilities.map((vuln) => vuln.cve_id));
    } catch (error) {
        console.error("Error reading existing vulnerabilities:", error);
        return new Set();
    }
}

function appendToFile(data, filename) {
    const filePath = path.resolve(filename);
    try {
        const existingData = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf-8").trim() : "[]";

        let jsonData = [];
        if (existingData && existingData !== "[]") {
            jsonData = JSON.parse(existingData);
        }

        jsonData.push(data);

        fs.writeFileSync(filePath, JSON.stringify(jsonData, null, 2));
        console.log(`Data for CVE ${data.cve_id} appended to: ${filePath}`);
    } catch (err) {
        console.error("Error appending data to file:", err);
    }
}

export async function processVulnerabilities(data, filename) {
    const vulnerabilities = extractVulnerabilities(data);
    const existingVulns = readExistingVulnerabilities(filename);
    let requestCount = 0;

    for (const vuln of vulnerabilities) {
        if (existingVulns.has(vuln.cve_id)) {
            console.log(`Skipping CVE ${vuln.cve_id} (Already Processed)`);
            continue;
        }

        console.log(`Processing CVE: ${vuln.cve_id}`);
        
        const osvDetails = await fetchOSVDetails(vuln.cve_id);
        if (!osvDetails) {
            console.warn(`No details found for CVE: ${vuln.cve_id}`);
            continue;
        }

        const geminiSummary = await processWithGemini(osvDetails);
        
        if (!geminiSummary || geminiSummary === "Error generating summary.") {
            console.warn(`No summary generated for CVE: ${vuln.cve_id}`);
        }

        const result = {
            cve_id: vuln.cve_id,
            severity: vuln.severity,
            components: vuln.components,
            date: vuln.date,
            summary: geminiSummary,
            modelVersion: "gemini-1.5-flash",
        };

        appendToFile(result, filename);
        existingVulns.add(vuln.cve_id);

        requestCount++;

        if (requestCount > 1 && requestCount % 15 == 0) {
            console.log("15 requests made. Sleeping for 1 minute...");
            await sleep(61000);
        }
    }

    console.log("Processing complete. Data saved to:", filename);
}

async function main() {
    const jsonUrl = "https://storage.googleapis.com/osv-android-api/v1/android_sdk_34.json";
    const filename = process.argv[2] || "SumPatches_output.json";

    try {
        console.log("Fetching JSON data...");
        const jsonData = await fetchJsonData(jsonUrl);

        console.log("Processing vulnerabilities...");
        await processVulnerabilities(jsonData, filename);

        console.log("Process completed successfully!");
    } catch (error) {
        console.error("An error occurred:", error.message);
    }
}

main();
