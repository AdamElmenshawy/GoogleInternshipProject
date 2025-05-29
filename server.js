import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 20000; // Use environment variable for the port if available

app.use(cors());
app.use(express.json());

// Define path to the output JSON file
// const outputFilePath = path.join(__dirname, "SumPatches_output.json");
const outputFilePath = new URL('./SumPatches_output.json', import.meta.url);

// Fetch vulnerabilities from the saved JSON file and serve it to the frontend
app.get("/api/vulnerabilities", (req, res) => {
  fs.readFile(outputFilePath, "utf8", (err, data) => {
    if (err) {
      console.error("Error reading SumPatches_output.json:", err.message);
      return res.status(500).json({ error: "Failed to read vulnerabilities data" });
    }

    try {
      const vulnerabilities = JSON.parse(data); // Parse the JSON data
      res.json(vulnerabilities); // Send the parsed data to the frontend
    } catch (parseError) {
      console.error("Error parsing SumPatches_output.json:", parseError.message);
      return res.status(500).json({ error: "Failed to parse vulnerabilities data" });
    }
  });
});

// Start the server and listen on the defined port
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
