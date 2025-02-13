import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { fetchJsonData, processVulnerabilities } from "./SumPatches.js";
dotenv.config();

const app = express();
const PORT = 10000;
// const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

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
    console.log('Server is running on port ${PORT}');
});
