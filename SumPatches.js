import { GoogleGenerativeAI } from "@google/generative-ai";
import axios from "axios";
import dotenv from "dotenv";

// Load environment variables from a .env file
dotenv.config();

const OSV_API_URL = "https://api.osv.dev/v1/vulns/";
const geminiApiKey = process.env.GEMINI_API_KEY;

if (!geminiApiKey) {
    throw new Error("Gemini API Key is missing. Please set GEMINI_API_KEY in your environment.");
}

// Initialize Gemini client
const genAI = new GoogleGenerativeAI(geminiApiKey);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Fetch JSON data from the URL
export async function fetchJsonData(url) {
    try {
        const response = await axios.get(url);
        return response.data;
    } catch (error) {
        console.error("Error fetching JSON data:", error.message);
        throw error;
    }
}

// Extract vulnerabilities from the JSON file
export function extractVulnerabilities(data) {
    const vulnerabilities = [];
    for (const date in data.vulnerabilities) {
        const patchesForDate = data.vulnerabilities[date];
        patchesForDate.forEach((vuln) => {
            const identifiers = vuln.asb_identifiers || [];
            identifiers.forEach((id) => {
                vulnerabilities.push({
                    id,
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

// Fetch detailed information about an identifier from the OSV API
export async function fetchOSVDetails(osvId) {
    try {
        const response = await axios.get(`${OSV_API_URL}${osvId}`);
        return response.data;
    } catch (error) {
        console.error(`Error fetching details for OSV ID ${osvId}:`, error.message);
        return null;
    }
}

// Sleep function to pause execution for a given time in milliseconds
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Process OSV data through Gemini AI to get a summary
export async function processWithGemini(osvDetails) {
    try {
        const prompt = `Analyze and summarize this security vulnerability in clear, non-technical terms:\n\n${JSON.stringify(osvDetails, null, 2)}`;
        const result = await model.generateContent(prompt);

        // Log the full response to debug
        console.log("Gemini API Response:", JSON.stringify(result, null, 2));

        // Check if the result contains the text property, or adjust accordingly
        const summary = result.response ? result.response.text() : "No summary returned";

        // Log the generated summary for debugging
        console.log("Generated Summary:", summary);

        return summary;
    } catch (error) {
        console.error("Error processing data with Gemini AI:", error.message);
        return "Error generating summary.";
    }
}

// Process vulnerabilities with rate limiting
export async function processVulnerabilities(data) {
    const vulnerabilities = extractVulnerabilities(data);
    const results = [];
    let requestCount = 0;

    for (const vuln of vulnerabilities) {
        console.log(`Processing OSV ID: ${vuln.id}`);
        
        const osvDetails = await fetchOSVDetails(vuln.id);
        if (!osvDetails) {
            console.warn(`No details found for OSV ID: ${vuln.id}`);
            continue;
        }

        const geminiSummary = await processWithGemini(osvDetails);
        
        // If there's no summary, log this for further debugging
        if (!geminiSummary || geminiSummary === "Error generating summary.") {
            console.warn(`No summary generated for OSV ID: ${vuln.id}`);
        }

        results.push({
            ...vuln,
            osvDetails,
            geminiSummary,
        });

        // Increment request count
        requestCount++;

        // If 15 requests have been made, wait for 1 minute before continuing
        if (requestCount > 1 && requestCount % 15 == 0) {
            console.log("15 requests made. Sleeping for 1 minute...");
            await sleep(61000); // Sleep for 1 minute (61,000 ms)
            // requestCount = 0; // Reset the request count after sleeping
        }
    }

    console.log("Processing complete. Processed vulnerabilities:", results.length);
    return results;
}

// Main function to run the workflow
async function main() {
    const jsonUrl = "https://storage.googleapis.com/osv-android-api/v1/android_sdk_34.json";

    try {
        console.log("Fetching JSON data...");
        const jsonData = await fetchJsonData(jsonUrl);

        console.log("Processing vulnerabilities...");
        const processedVulnerabilities = await processVulnerabilities(jsonData);

        console.log("Final Output:", JSON.stringify(processedVulnerabilities, null, 2));
    } catch (error) {
        console.error("An error occurred:", error.message);
    }
}

// Run the main function
main();
