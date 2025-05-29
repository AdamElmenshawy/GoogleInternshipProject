import React from "react";
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
// Update this import path
import data from "../../data/SumPatches_output.json";

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const Dashboard = ({ monthData, monthName }) => {
  const chartRef = React.useRef(null);

  // Calculate severity counts for pie chart
  const severityCounts = monthData.reduce((acc, item) => {
    const severity = item.severity.toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [{
      data: [
        severityCounts.critical || 0,
        severityCounts.high || 0,
        severityCounts.medium || 0,
        severityCounts.low || 0
      ],
      backgroundColor: ["#FF5733", "#FF8C00", "#FFEB3B", "#4CAF50"],
    }],
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
                  <TableCell><strong>Severity</strong></TableCell>
                  <TableCell><strong>Components</strong></TableCell>
                  <TableCell><strong>Date</strong></TableCell>
                  <TableCell><strong>Summary</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {monthData.map((row) => (
                  <TableRow key={row.cve_id}>
                    <TableCell>{row.cve_id}</TableCell>
                    <TableCell>{row.severity}</TableCell>
                    <TableCell>{row.components}</TableCell>
                    <TableCell>{row.date}</TableCell>
                    <TableCell>{row.summary}</TableCell>
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
          Total vulnerabilities this month: {monthData.length}
          Critical: {severityCounts.critical || 0}
          High: {severityCounts.high || 0}
          Medium: {severityCounts.medium || 0}
          Low: {severityCounts.low || 0}
        </Typography>
      </Box>
    </Box>
  );
};

export async function getStaticPaths() {
  const months = ["2024-01", "2024-02", "2024-03", "2024-04", "2024-05", "2024-06", 
                 "2024-07", "2024-08", "2024-09", "2024-10", "2024-11", "2024-12"];
  const paths = months.map((month) => ({
    params: { month },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps({ params }) {
  // Filter data based on the month
  const monthData = data.filter(item => {
    const itemDate = new Date(item.date);
    const [year, month] = params.month.split('-');
    return itemDate.getFullYear() === parseInt(year) && 
           (itemDate.getMonth() + 1) === parseInt(month);
  });

  const monthName = new Date(params.month + "-01").toLocaleString('default', { month: 'long', year: 'numeric' });

  return { props: { monthData, monthName } };
}

export default Dashboard;