import React from "react";
import { Container, Typography, Box, Grid, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from "@mui/material";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { useRouter } from 'next/router';

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const UpdatePage = ({ updateData }) => {
  const router = useRouter();
  const { updateId } = router.query;

  const data = {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        data: updateData.chartData,
        backgroundColor: ["#FF6384", "#FFCE56", "#36A2EB"],
        hoverBackgroundColor: ["#FF6384", "#FFCE56", "#36A2EB"],
      },
    ],
  };

  return (
    <Container>
      <Box p={3}>
        <Typography variant="h4" component="h1" gutterBottom>
          Android Security Bulletin - {updateId}
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
                    <TableCell><strong>Versions</strong></TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {updateData.cveData.map((row) => (
                    <TableRow key={row.cve}>
                      <TableCell>{row.cve}</TableCell>
                      <TableCell>{row.references}</TableCell>
                      <TableCell>{row.type}</TableCell>
                      <TableCell>{row.severity}</TableCell>
                      <TableCell>{row.versions}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box display="flex" justifyContent="center" mb={4}>
              <Box width="100%">
                <Pie data={data} />
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
    </Container>
  );
};

export async function getStaticPaths() {
  // Fetch or define your update IDs here
  const updateIds = ["2024-01", "2024-02", "2024-03"]; // Example update IDs

  const paths = updateIds.map((id) => ({
    params: { updateId: id },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps({ params }) {
  const { updateId } = params;

  // Fetch or define your update data here
  const updateData = {
    chartData: [2, 0, 0], // Example chart data
    cveData: [
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
      // Add more data as needed
    ],
  };

  return { props: { updateData } };
}

export default UpdatePage;