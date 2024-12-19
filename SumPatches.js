import axios from "axios";

const OSV_API_URL = "https://api.osv.dev/v1/vulns/"; // Base URL for OSV API
const GEMINI_API_URL = "https://api.gemini.openai.com/v1/process"; // Replace with the correct Gemini API endpoint
const geminiApiKey = "AIzaSyBc_m3ylPtp3EVpPBeI4gBRkqpduTNryv8"; // Gemini API Key

// Function to fetch JSON data from the URL
async function fetchJsonData(url) {
    try {
        const response = await axios.get(url);
        return response.data;
    } catch (error) {
        console.error('Error fetching JSON data:', error.message);
        throw error;
    }
}

// Function to process vulnerabilities and fetch OSV and Gemini details
async function processVulnerabilities(data) {
    try {
        if (!data.vulnerabilities) {
            throw new Error('Invalid JSON structure: Missing vulnerabilities object');
        }

        const vulnerabilities = [];
        // Flatten the vulnerabilities array with relevant details
        for (const date in data.vulnerabilities) {
            const patchesForDate = data.vulnerabilities[date];
            patchesForDate.forEach(vuln => {
                vulnerabilities.push({
                    id: vuln.id || 'Unknown ID',
                    description: vuln.description || 'No description available',
                    severity: vuln.severity || 'Unknown severity',
                    fixedIn: (vuln.references || [])
                        .filter(ref => ref.type === 'FIX')
                        .map(ref => ref.url).join(', ') || 'No specific fix URL provided.',
                    date,
                });
            });
        }

        // Fetch details from OSV and process them through Gemini API
        const processedVulnerabilities = await processWithGeminiApi(vulnerabilities);
        console.log('Processed vulnerabilities:', processedVulnerabilities);
    } catch (error) {
        console.error('Error processing vulnerabilities:', error.message);
        throw error;
    }
}

// Function to fetch OSV details and run them through Gemini API
async function processWithGeminiApi(vulnerabilities) {
    try {
        const results = vulnerabilities.map(async (vuln) => {
            const vulnId = vuln.id;
            if (!vulnId || vulnId === 'Unknown ID') {
                console.warn('Skipping vulnerability with missing or unknown ID.');
                return null;
            }

            try {
                // Fetch details from OSV API
                const response = await axios.get(`${OSV_API_URL}${vulnId}`);
                const osvDetails = response.data;

                // Run OSV details through Gemini API
                const geminiResponse = await axios.post(
                    GEMINI_API_URL,
                    {
                        cveDetails: osvDetails, // Send OSV details as payload
                    },
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            Authorization: `Bearer ${geminiApiKey}`, // Use Gemini API Key
                        },
                    }
                );

                return {
                    id: vulnId,
                    description: vuln.description,
                    severity: vuln.severity,
                    fixedIn: vuln.fixedIn,
                    date: vuln.date,
                    osvDetails,
                    geminiOutput: geminiResponse.data, // Include processed Gemini API output
                };
            } catch (error) {
                console.error(`Error processing vulnerability ID ${vulnId}:`, error.message);
                return null;
            }
        });

        // Await all queries and filter out null results
        const processedResults = await Promise.all(results);
        return processedResults.filter(result => result !== null);
    } catch (error) {
        console.error('Error processing vulnerabilities with Gemini API:', error.message);
        throw error;
    }
}

// Main function to run the workflow
async function main() {
    const jsonUrl = 'https://storage.googleapis.com/osv-android-api/v1/android_sdk_34.json';
    try {
        console.log('Fetching JSON data...');
        const jsonData = await fetchJsonData(jsonUrl);

        console.log('Processing vulnerabilities...');
        await processVulnerabilities(jsonData);
    } catch (error) {
        console.error('An error occurred:', error.message);
    }
}

// Run the main function
main();
