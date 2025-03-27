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

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const EmptyDashboard = ({ monthName }) => {
  const chartRef = React.useRef(null);

  const chartData = {
    labels: ["EoP", "ID", "DoS"],
    datasets: [
      {
        data: [0, 0, 0], // Empty data
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
                {/* Empty table body */}
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
  const monthName = new Date(params.month + "-01").toLocaleString('default', { month: 'long', year: 'numeric' });

  return { props: { monthName } };
}

export default EmptyDashboard;