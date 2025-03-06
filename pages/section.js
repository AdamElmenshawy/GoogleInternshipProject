import React, { useState, useEffect } from "react";
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

ChartJS.register(ArcElement, Tooltip, Legend);

const SectionPage = ({ sectionName }) => {
  const [sectionData, setSectionData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`http://localhost:10000/api/sections/${sectionName}`) // Adjust API endpoint
      .then((response) => response.json())
      .then((data) => {
        setSectionData(data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
        setLoading(false);
      });
  }, [sectionName]);

  if (loading) return <Typography>Loading...</Typography>;

  const vulnerabilityCounts = sectionData.reduce(
    (acc, item) => {
      acc[item.type] = (acc[item.type] || 0) + 1;
      return acc;
    },
    { EoP: 0, ID: 0, DoS: 0 }
  );

  const chartData = {
    labels: ["EoP", "ID", "DoS"],
    datasets: [
      {
        data: [vulnerabilityCounts.EoP, vulnerabilityCounts.ID, vulnerabilityCounts.DoS],
        backgroundColor: ["#FF5733", "#FF8C00", "#FFEB3B"],
      },
    ],
  };

  return (
    <Box p={3}>
      <Typography variant="h4">{sectionName} Vulnerabilities</Typography>
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
                {sectionData.length > 0 ? (
                  sectionData.map((row) => (
                    <TableRow key={row.cve}>
                      <TableCell>{row.cve}</TableCell>
                      <TableCell>{row.references}</TableCell>
                      <TableCell>{row.type}</TableCell>
                      <TableCell>{row.severity}</TableCell>
                      <TableCell>{row.versions || row.subcomponent}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={5} align="center">No vulnerabilities reported.</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
        <Grid item xs={12} md={4}>
          <Pie data={chartData} />
        </Grid>
      </Grid>
    </Box>
  );
};

export async function getServerSideProps({ params }) {
  return { props: { sectionName: params.section } };
}

export default SectionPage;
