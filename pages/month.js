import React, { useEffect, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
  Box,
  Grid,
} from "@mui/material";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const EmptyDashboard = ({ monthName }) => {
  const [vulnerabilities, setVulnerabilities] = useState([]); // State to hold the fetched data

  const chartRef = React.useRef(null);

  const chartData = {
    labels: ["EoP", "ID", "DoS"],
    datasets: [
      {
        data: vulnerabilities.reduce(
          (acc, item) => {
            acc[item.type] = (acc[item.type] || 0) + 1;
            return acc;
          },
          { EoP: 0, ID: 0, DoS: 0 } // Initial values
        ),
        backgroundColor: ["#FF5733", "#FF8C00", "#FFEB3B"],
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top",
      },
    },
  };

  useEffect(() => {
    // Fetch vulnerabilities from the backend API
    fetch("http://localhost:10000/api/vulnerabilities")
      .then((response) => response.json())
      .then((data) => setVulnerabilities(data)) // Store fetched data in state
      .catch((error) => console.error("Error fetching data:", error));
  }, []);

  return (
    <Box p={3}>
      <Typography variant="h4" component="h1" gutterBottom>
        {monthName} Vulnerabilities
      </Typography>
      <Grid container spacing={4}>
        <Grid item xs={12} md={8}>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell><strong>CVE</strong></TableCell>
                  <TableCell><strong>References</strong></TableCell>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Severity</strong></TableCell>
                  <TableCell><strong>Updated AOSP Versions</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {vulnerabilities.map((row) => (
                  <TableRow key={row.cve}>
                    <TableCell>{row.cve}</TableCell>
                    <TableCell>{row.references}</TableCell>
                    <TableCell>{row.type}</TableCell>
                    <TableCell>{row.severity}</TableCell>
                    <TableCell>{row.versions || row.subcomponent}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
        <Grid item xs={12} md={4}>
          <Box display="flex" justifyContent="center" mb={4}>
            <Box width="100%">
              <Pie ref={chartRef} data={chartData} options={chartOptions} />
            </Box>
          </Box>
        </Grid>
      </Grid>
      <Box mt={4}>
        <Typography variant="h5" component="h2" gutterBottom>
          AI Overview
        </Typography>
        <Typography variant="body1">
          This section provides an overview of the AI analysis and insights.
          You can add more detailed information here based on your specific requirements.
        </Typography>
      </Box>
    </Box>
  );
};

export default EmptyDashboard;
