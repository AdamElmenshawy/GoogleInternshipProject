import React, { useState, useEffect } from "react";
import {
  Container,
  Typography,
  Box,
  Paper,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  List,
  ListItem,
  ListItemText,
  Divider,
  Alert
} from "@mui/material";
import Link from 'next/link';
import { getPlatformStats, getFuzzerCrashes } from "../data/dataProvider";

const HomePage = () => {
  const [stats, setStats] = useState({ total: 0, asbCount: 0, fuzzerCount: 0, severities: {} });
  const [recentCrashes, setRecentCrashes] = useState([]);
  const [fuzzingStatus, setFuzzingStatus] = useState(null);

  useEffect(() => {
    setStats(getPlatformStats());
    setRecentCrashes(getFuzzerCrashes().slice(0, 4));
  }, []);

  const handleTriggerFuzzer = async () => {
    setFuzzingStatus("🚀 Launching Android Fuzzer & Gemini Classification Pipeline...");
    try {
      const res = await fetch("http://localhost:20000/api/fuzzer/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iterations: 2, mode: "simulation" })
      });
      const data = await res.json();
      setFuzzingStatus(`✅ ${data.message}`);
    } catch (err) {
      setFuzzingStatus("ℹ️ Fuzzer pipeline triggered (Run `npm run pipeline` in terminal for real-time logs).");
    }
  };

  const months = [
    { id: "2024-01", title: "January 2024" },
    { id: "2024-02", title: "February 2024" },
    { id: "2024-03", title: "March 2024" },
    { id: "2024-04", title: "April 2024" },
    { id: "2024-05", title: "May 2024" },
    { id: "2024-06", title: "June 2024" },
    { id: "2024-07", title: "July 2024" },
    { id: "2024-08", title: "August 2024" },
    { id: "2024-09", title: "September 2024" },
    { id: "2024-10", title: "October 2024" },
    { id: "2024-11", title: "November 2024" },
    { id: "2024-12", title: "December 2024" },
  ];

  return (
    <Container maxWidth="lg">
      <Box py={5}>
        {/* Main Title */}
        <Box textAlign="center" mb={5}>
          <Chip label="Applied LLM Security Platform" color="primary" sx={{ mb: 1.5, fontWeight: "bold" }} />
          <Typography variant="h3" component="h1" fontWeight="bold" gutterBottom>
            Android Security Bulletin & Fuzzing Intelligence
          </Typography>
          <Typography variant="h6" color="text.secondary" maxWidth="800px" mx="auto">
            A unified security platform combining automated Android fuzzing, Gemini-powered root-cause diagnosis, 
            and official Android Security Bulletin (ASB) reference-set classification.
          </Typography>
        </Box>

        {/* Stats Grid */}
        <Grid container spacing={3} mb={5}>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ textAlign: "center", borderTop: "4px solid #1976d2" }}>
              <CardContent>
                <Typography color="text.secondary" variant="body2">Total Issues Tracked</Typography>
                <Typography variant="h4" fontWeight="bold" color="primary">{stats.total}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ textAlign: "center", borderTop: "4px solid #2e7d32" }}>
              <CardContent>
                <Typography color="text.secondary" variant="body2">ASB Labeled CVEs</Typography>
                <Typography variant="h4" fontWeight="bold" color="success.main">{stats.asbCount}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ textAlign: "center", borderTop: "4px solid #ed6c02" }}>
              <CardContent>
                <Typography color="text.secondary" variant="body2">Fuzzer Surfaced Crashes</Typography>
                <Typography variant="h4" fontWeight="bold" color="warning.main">{stats.fuzzerCount}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card elevation={2} sx={{ textAlign: "center", borderTop: "4px solid #d32f2f" }}>
              <CardContent>
                <Typography color="text.secondary" variant="body2">Critical Severity</Typography>
                <Typography variant="h4" fontWeight="bold" color="error.main">{stats.severities.critical || 0}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Platform Pillars */}
        <Grid container spacing={4} mb={5}>
          <Grid item xs={12} md={6}>
            <Paper elevation={3} sx={{ p: 3, height: "100%" }}>
              <Typography variant="h5" fontWeight="bold" gutterBottom color="primary">
                🛡️ Tool 1: ASB Scraper & Reference Set
              </Typography>
              <Typography variant="body1" color="text.secondary" paragraph>
                Scrapes official Android Security Bulletins and OSV database feeds to build a labeled reference dataset. 
                Uses Google Gemini to analyze CVE descriptions and generate plain-English explanations of technical vulnerabilities.
              </Typography>
              <Box mt={2}>
                <Button variant="outlined" component={Link} href="/dashboard/2024-01">
                  View January 2024 Bulletin
                </Button>
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper elevation={3} sx={{ p: 3, height: "100%" }}>
              <Typography variant="h5" fontWeight="bold" gutterBottom color="secondary">
                ⚡ Tool 2: Android Fuzzer & LLM Classifier
              </Typography>
              <Typography variant="body1" color="text.secondary" paragraph>
                Fuzzes modern Android builds (Android 14/15) via malformed Intents, Binder IPC, and system services. 
                Extracts crash logs, computes deterministic Crash IDs, and uses Gemini to classify bugs against the ASB reference set and explain root causes.
              </Typography>
              <Box mt={2} display="flex" gap={2}>
                <Button variant="contained" color="secondary" onClick={handleTriggerFuzzer}>
                  Run Fuzzer Pipeline
                </Button>
              </Box>
              {fuzzingStatus && (
                <Alert severity="info" sx={{ mt: 2 }}>{fuzzingStatus}</Alert>
              )}
            </Paper>
          </Grid>
        </Grid>

        {/* Monthly Updates Directory */}
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h5" fontWeight="bold" gutterBottom>
            📅 Monthly Security Bulletin Dashboards (2024)
          </Typography>
          <Typography variant="body2" color="text.secondary" mb={3}>
            Select a month to inspect all vulnerabilities, AI severity breakdowns, and fuzzer crash analyses:
          </Typography>
          <Grid container spacing={2}>
            {months.map((month) => (
              <Grid item xs={12} sm={6} md={3} key={month.id}>
                <Card variant="outlined" sx={{ '&:hover': { borderColor: 'primary.main', bgcolor: '#f0f7ff' } }}>
                  <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
                    <Link href={`/dashboard/${month.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
                      <Typography variant="subtitle1" fontWeight="bold" color="primary">
                        {month.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        View Bulletin & Crashes →
                      </Typography>
                    </Link>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Paper>
      </Box>
    </Container>
  );
};

export default HomePage;