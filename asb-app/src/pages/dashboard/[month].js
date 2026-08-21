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
  Tabs,
  Tab,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  Breadcrumbs
} from "@mui/material";
import Link from "next/link";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import data from "../../data/SumPatches_output.json";

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const Dashboard = ({ initialMonthData, monthName, monthId }) => {
  const chartRef = React.useRef(null);
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selectedIssue, setSelectedIssue] = useState(null);

  // Filter items based on active tab
  const filteredData = initialMonthData.filter((item) => {
    const isFuzzer = item.source === "fuzzer" || (item.cve_id && item.cve_id.startsWith("CRASH-"));
    if (sourceFilter === "fuzzer") return isFuzzer;
    if (sourceFilter === "asb") return !isFuzzer;
    return true;
  });

  // Calculate severity counts for pie chart
  const severityCounts = filteredData.reduce((acc, item) => {
    const severity = (item.severity || "unknown").toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
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
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link href="/" style={{ textDecoration: 'none', color: '#1976d2' }}>
          ← Back to Bulletins Overview
        </Link>
        <Typography color="text.primary">{monthName}</Typography>
      </Breadcrumbs>

      <Typography variant="h3" component="h1" fontWeight="bold" gutterBottom>
        {monthName} Security Bulletin & Fuzzer Reports
      </Typography>

      {/* Filter Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={sourceFilter}
          onChange={(e, val) => setSourceFilter(val)}
          indicatorColor="primary"
          textColor="primary"
          variant="fullWidth"
        >
          <Tab value="all" label={`All Issues (${initialMonthData.length})`} />
          <Tab value="asb" label={`Official ASB CVEs (${initialMonthData.filter(d => d.source !== 'fuzzer' && !d.cve_id?.startsWith('CRASH-')).length})`} />
          <Tab value="fuzzer" label={`Fuzzer Discovered Crashes (${initialMonthData.filter(d => d.source === 'fuzzer' || d.cve_id?.startsWith('CRASH-')).length})`} />
        </Tabs>
      </Paper>

      {/* Main Grid: Table & Pie Chart */}
      <Grid container spacing={4}>
        <Grid item xs={12} lg={8}>
          <TableContainer component={Paper} elevation={3}>
            <Table size="medium">
              <TableHead sx={{ bgcolor: "#f5f5f5" }}>
                <TableRow>
                  <TableCell><strong>Source</strong></TableCell>
                  <TableCell><strong>ID</strong></TableCell>
                  <TableCell><strong>Component</strong></TableCell>
                  <TableCell><strong>Type</strong></TableCell>
                  <TableCell><strong>Severity</strong></TableCell>
                  <TableCell><strong>Summary / Root Cause</strong></TableCell>
                  <TableCell align="center"><strong>Details</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredData.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                      <Typography color="text.secondary">No records found for this filter selection.</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredData.map((row) => {
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
                        <TableCell>{row.components || "Framework"}</TableCell>
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

        {/* Chart Column */}
        <Grid item xs={12} lg={4}>
          <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" fontWeight="bold" gutterBottom align="center">
              Severity Distribution ({sourceFilter.toUpperCase()})
            </Typography>
            <Box height="260px" display="flex" justifyContent="center" alignItems="center">
              {filteredData.length > 0 ? (
                <Pie ref={chartRef} data={chartData} options={chartOptions} />
              ) : (
                <Typography color="text.secondary">No data to display</Typography>
              )}
            </Box>
          </Paper>

          {/* AI Overview Box */}
          <Paper elevation={3} sx={{ p: 3, bgcolor: "#f8faff", border: "1px solid #e3f2fd" }}>
            <Typography variant="h6" fontWeight="bold" color="primary" gutterBottom>
              🤖 AI Intelligence Overview
            </Typography>
            <Typography variant="body2" paragraph>
              <strong>Total Filtered:</strong> {filteredData.length} issues
            </Typography>
            <Typography variant="body2" paragraph>
              <strong>Critical:</strong> {severityCounts.critical || 0} &nbsp;|&nbsp; 
              <strong>High:</strong> {severityCounts.high || 0} &nbsp;|&nbsp; 
              <strong>Medium:</strong> {severityCounts.medium || 0} &nbsp;|&nbsp; 
              <strong>Low:</strong> {severityCounts.low || 0}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Generated via Google Gemini applied LLM security classification pipeline.
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
            <Grid container spacing={2} mb={2}>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Affected Component</Typography>
                <Typography variant="subtitle2">{selectedIssue.components}</Typography>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="caption" color="text.secondary">Classification Type</Typography>
                <Typography variant="subtitle2">{selectedIssue.type || "Vulnerability"}</Typography>
              </Grid>
              {selectedIssue.target_build && (
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">Target Android Build</Typography>
                  <Typography variant="subtitle2">{selectedIssue.target_build}</Typography>
                </Grid>
              )}
            </Grid>

            <Divider sx={{ my: 1.5 }} />

            <Typography variant="subtitle1" fontWeight="bold" color="primary" gutterBottom>
              🧠 Gemini Root-Cause Explanation (Non-Technical)
            </Typography>
            <Typography variant="body1" paragraph sx={{ bgcolor: "#fafafa", p: 2, borderRadius: 1 }}>
              {selectedIssue.summary}
            </Typography>

            {selectedIssue.classification_reasoning && (
              <>
                <Typography variant="subtitle1" fontWeight="bold" color="secondary" gutterBottom>
                  🏷️ Reference-Set Classification Reasoning
                </Typography>
                <Typography variant="body2" paragraph sx={{ bgcolor: "#f3e5f5", p: 2, borderRadius: 1 }}>
                  {selectedIssue.classification_reasoning}
                </Typography>
              </>
            )}

            {selectedIssue.stack_trace && (
              <>
                <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                  📜 Fault Signal & Backtrace
                </Typography>
                <Box 
                  component="pre" 
                  sx={{ 
                    bgcolor: "#1e1e1e", 
                    color: "#00ff66", 
                    p: 2, 
                    borderRadius: 1, 
                    overflowX: "auto", 
                    fontSize: "0.8rem",
                    fontFamily: "monospace" 
                  }}
                >
                  {selectedIssue.fault_signal && `[SIGNAL] ${selectedIssue.fault_signal}\n`}
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
  const months = [
    "2024-01", "2024-02", "2024-03", "2024-04", "2024-05", "2024-06",
    "2024-07", "2024-08", "2024-09", "2024-10", "2024-11", "2024-12"
  ];
  const paths = months.map((month) => ({
    params: { month },
  }));

  return { paths, fallback: false };
}

export async function getStaticProps({ params }) {
  const [year, month] = params.month.split('-');
  
  // Filter all items for the month (both ASB and Fuzzer items)
  const initialMonthData = (data || []).filter((item) => {
    if (!item.date) return false;
    const itemDate = new Date(item.date);
    return itemDate.getFullYear() === parseInt(year) && 
           (itemDate.getMonth() + 1) === parseInt(month);
  });

  const monthName = new Date(params.month + "-01").toLocaleString('default', { month: 'long', year: 'numeric' });

  return { props: { initialMonthData, monthName, monthId: params.month } };
}

export default Dashboard;