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
// import { getDataByMonth } from "../../data/dataProvider"; // Adjust the import based on your data source

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const Dashboard = ({ monthData, monthName }) => {
  const chartRef = React.useRef(null);

  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [30, 50, 15, 5], // Example data, replace with actual data
        backgroundColor: ["#FF5733", "#FF8C00", "#FFEB3B", "#4CAF50"],
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
                {monthData.map((row) => (
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

export async function getStaticPaths() {
  const months = ["2024-01", "2024-02", "2024-03", "2024-04", "2024-05", "2024-06", "2024-07", "2024-08", "2024-09", "2024-10", "2024-11", "2024-12"];
  const paths = months.map((month) => ({
    params: { month },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps({ params }) {
  const monthData = [
    {
      cve: "CVE-2024-43762",
      references: "A-340239088",
      type: "EoP",
      severity: "High",
      versions: "12, 12L, 13, 14, 15",
    },
    {
      cve: "CVE-2024-43764",
      references: "A-317048495",
      type: "EoP",
      severity: "High",
      versions: "13, 14",
    },
    {
      cve: "CVE-2024-43769",
      references: "A-360807442",
      type: "EoP",
      severity: "High",
      versions: "13, 14, 15",
    },
  ]; 
//   getDataByMonth(params.month); // Fetch data based on the month
  const monthName = new Date(params.month + "-01").toLocaleString('default', { month: 'long', year: 'numeric' });

  return { props: { monthData, monthName } };
}

export default Dashboard;