import React, { useState } from "react";
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
  Chip,
  Breadcrumbs,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from "@mui/material";
import Link from "next/link";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { getDataBySection } from "../../data/dataProvider";

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const SectionPage = ({ sectionData = [], sectionName, sectionId }) => {
  const chartRef = React.useRef(null);
  const [selectedIssue, setSelectedIssue] = useState(null);

  // Group by severity
  const severityCounts = sectionData.reduce((acc, item) => {
    const s = (item.severity || "unknown").toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [
          severityCounts.critical || 0,
          severityCounts.high || 0,
          severityCounts.medium || 0,
          severityCounts.low || 0,
        ],
        backgroundColor: ["#d32f2f", "#ed6c02", "#fbc02d", "#2e7d32"],
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

  const getSeverityColor = (severity) => {
    switch ((severity || "").toLowerCase()) {
      case "critical": return "error";
      case "high": return "warning";
      case "medium": return "info";
      case "low": return "success";
      default: return "default";
    }
  };

  return (
    <Box p={4} maxWidth="1400px" mx="auto">
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link href="/" style={{ textDecoration: 'none', color: '#1976d2' }}>
          ← Back to Bulletins Overview
        </Link>
        <Typography color="text.primary">{sectionName} Component</Typography>
      </Breadcrumbs>

      <Typography variant="h3" component="h1" fontWeight="bold" gutterBottom>
        {sectionName} Security Analysis
      </Typography>

      <Grid container spacing={4}>
        <Grid item xs={12} lg={8}>
          <TableContainer component={Paper} elevation={3}>
            <Table size="medium">
              <TableHead sx={{ bgcolor: "#f5f5f5" }}>
                <TableRow>
                  <TableCell><strong>Source</strong></TableCell>
                  <TableCell><strong>Identifier</strong></TableCell>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Severity</strong></TableCell>
                  <TableCell><strong>Summary / Diagnosis</strong></TableCell>
                  <TableCell align="center"><strong>Action</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {sectionData.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                      <Typography color="text.secondary">No issues found for {sectionName}.</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  sectionData.map((row) => {
                    const isFuzzer = row.source === "fuzzer" || (row.cve_id && row.cve_id.startsWith("CRASH-"));
                    return (
                      <TableRow key={row.cve_id || row.crash_id} hover>
                        <TableCell>
                          <Chip 
                            label={isFuzzer ? "FUZZER" : "ASB"} 
                            color={isFuzzer ? "secondary" : "primary"} 
                            size="small" 
                            variant="outlined" 
                          />
                        </TableCell>
                        <TableCell>
                          <strong>{row.cve_id || row.crash_id}</strong>
                        </TableCell>
                        <TableCell>
                          <Chip label={row.type || "Vulnerability"} size="small" variant="filled" />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={(row.severity || "unknown").toUpperCase()} 
                            color={getSeverityColor(row.severity)} 
                            size="small" 
                          />
                        </TableCell>
                        <TableCell sx={{ maxWidth: "300px" }}>
                          <Typography variant="body2" noWrap title={row.summary}>
                            {row.summary}
                          </Typography>
                        </TableCell>
                        <TableCell align="center">
                          <Button size="small" variant="outlined" onClick={() => setSelectedIssue(row)}>
                            Inspect
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" fontWeight="bold" gutterBottom align="center">
              {sectionName} Severity Breakdown
            </Typography>
            <Box height="260px" display="flex" justifyContent="center" alignItems="center">
              {sectionData.length > 0 ? (
                <Pie ref={chartRef} data={chartData} options={chartOptions} />
              ) : (
                <Typography color="text.secondary">No data to display</Typography>
              )}
            </Box>
          </Paper>

          <Paper elevation={3} sx={{ p: 3, bgcolor: "#f8faff", border: "1px solid #e3f2fd" }}>
            <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
              🔍 Component Intelligence
            </Typography>
            <Typography variant="body2" paragraph>
              Total Issues in {sectionName}: <strong>{sectionData.length}</strong>
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Aggregated from official ASB bulletins and live Android fuzzer campaigns.
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Details Modal */}
      {selectedIssue && (
        <Dialog open={Boolean(selectedIssue)} onClose={() => setSelectedIssue(null)} maxWidth="md" fullWidth>
          <DialogTitle sx={{ bgcolor: "#f5f5f5", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Box display="flex" alignItems="center" gap={1}>
              <Chip 
                label={(selectedIssue.source || (selectedIssue.cve_id?.startsWith('CRASH-') ? 'fuzzer' : 'asb')).toUpperCase()} 
                color={selectedIssue.source === 'fuzzer' ? 'secondary' : 'primary'} 
              />
              <Typography variant="h6" fontWeight="bold">{selectedIssue.cve_id || selectedIssue.crash_id}</Typography>
            </Box>
            <Chip 
              label={(selectedIssue.severity || "unknown").toUpperCase()} 
              color={getSeverityColor(selectedIssue.severity)} 
            />
          </DialogTitle>
          <DialogContent dividers>
            <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>
              Summary / Diagnosis
            </Typography>
            <Typography variant="body1" paragraph sx={{ bgcolor: "#fafafa", p: 2, borderRadius: 1 }}>
              {selectedIssue.summary}
            </Typography>
            {selectedIssue.stack_trace && (
              <>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  Fault Signal & Backtrace
                </Typography>
                <Box component="pre" sx={{ bgcolor: "#1e1e1e", color: "#00ff66", p: 2, borderRadius: 1, overflowX: "auto", fontSize: "0.8rem" }}>
                  {selectedIssue.stack_trace}
                </Box>
              </>
            )}
          </DialogContent>
          <DialogActions sx={{ p: 2 }}>
            <Button onClick={() => setSelectedIssue(null)} variant="contained">Close</Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};

export async function getStaticPaths() {
  const sections = ["kernel", "vendor", "framework", "media"];
  const paths = sections.map((section) => ({
    params: { section },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps({ params }) {
  const sectionData = getDataBySection(params.section);
  const sectionName = params.section.charAt(0).toUpperCase() + params.section.slice(1).replace(/-/g, ' ');

  return { props: { sectionData, sectionName, sectionId: params.section } };
}

export default SectionPage;
