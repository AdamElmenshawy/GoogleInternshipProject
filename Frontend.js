
"use client";

import React, { useRef } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Link,
} from "@mui/material";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const Dashboard = () => {
  const chartRef = useRef(null);

  const cveData = [
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

  const chartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [30, 50, 15, 5],
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
    <div style={styles.container}>
      {/* Previous Updates Section */}
      <div style={styles.previousUpdates}>
        <h3 style={styles.sectionTitle}>Previous Updates</h3>
        <p>No previous updates available. Add content here dynamically.</p>
      </div>

      {/* Main Content Section */}
      <div style={styles.mainContent}>
        {/* CVE Table and Graphs */}
        <div style={styles.tableAndGraph}>
          {/* CVE Table Section */}
          <div style={styles.cveTable}>
            <h3 style={styles.sectionTitle}>CVE Table</h3>
            <TableContainer component={Paper} style={styles.tableContainer}>
              <Table>
                <TableHead>
                  <TableRow style={styles.tableHeader}>
                    <TableCell style={styles.headerText}>
                      <strong>CVE</strong>
                    </TableCell>
                    <TableCell style={styles.headerText}>
                      <strong>References</strong>
                    </TableCell>
                    <TableCell style={styles.headerText}>
                      <strong>Type</strong>
                    </TableCell>
                    <TableCell style={styles.headerText}>
                      <strong>Severity</strong>
                    </TableCell>
                    <TableCell style={styles.headerText}>
                      <strong>Updated AOSP Versions</strong>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {cveData.map((row, index) => (
                    <TableRow key={index} hover>
                      <TableCell>{row.cve}</TableCell>
                      <TableCell>
                        <Link
                          href={`https://example.com/${row.references}`}
                          target="_blank"
                          rel="noopener"
                          style={styles.link}
                        >
                          {row.references}
                        </Link>
                      </TableCell>
                      <TableCell>{row.type}</TableCell>
                      <TableCell>{row.severity}</TableCell>
                      <TableCell>{row.versions}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </div>

          {/* Pie Chart Section */}
          <div style={styles.graphForm}>
            <h3 style={styles.sectionTitle}>Severity Distribution</h3>
            <div style={{ width: "300px", height: "300px", margin: "0 auto" }}>
              <Pie ref={chartRef} data={chartData} options={chartOptions} />
            </div>
          </div>
        </div>

        {/* AI Overview Section */}
        <div style={styles.aiOverview}>
          <h3 style={styles.sectionTitle}>AI Overview/What This Means:</h3>
          <textarea
            style={styles.textArea}
            placeholder="Add your explanation here..."
          ></textarea>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: "grid",
    gridTemplateColumns: "0.7fr 3.3fr",
    gap: "20px",
    padding: "20px",
    backgroundColor: "#F5F5F5",
    fontFamily: "Arial, sans-serif",
  },
  previousUpdates: {
    border: "1px solid #D2E9E3",
    borderRadius: "8px",
    padding: "15px",
    height: "calc(100vh - 40px)",
    backgroundColor: "#FFFFFF",
    boxShadow: "0px 2px 4px rgba(0, 0, 0, 0.1)",
    overflowY: "auto",
  },
  sectionTitle: {
    color: "#073042",
    marginBottom: "10px",
  },
  mainContent: {
    display: "grid",
    gridTemplateRows: "auto auto",
    gap: "20px",
  },
  tableAndGraph: {
    display: "grid",
    gridTemplateColumns: "2fr 1fr",
    gap: "20px",
  },
  cveTable: {
    border: "1px solid #D2E9E3",
    borderRadius: "8px",
    padding: "15px",
    backgroundColor: "#FFFFFF",
    boxShadow: "0px 2px 4px rgba(0, 0, 0, 0.1)",
  },
  tableContainer: {
    maxHeight: "300px",
  },
  tableHeader: {
    backgroundColor: "#3DDC84",
  },
  headerText: {
    color: "#FFFFFF",
  },
  link: {
    color: "#3DDC84",
    textDecoration: "none",
  },
  graphForm: {
    border: "1px solid #D2E9E3",
    borderRadius: "8px",
    padding: "15px",
    backgroundColor: "#FFFFFF",
    boxShadow: "0px 2px 4px rgba(0, 0, 0, 0.1)",
    textAlign: "center",
  },
  aiOverview: {
    border: "1px solid #D2E9E3",
    borderRadius: "8px",
    padding: "15px",
    backgroundColor: "#FFFFFF",
    boxShadow: "0px 2px 4px rgba(0, 0, 0, 0.1)",
    height: "200px",
    display: "flex",
    flexDirection: "column",
    justifyContent: "space-between",
  },
  textArea: {
    width: "100%",
    height: "calc(100% - 30px)",
    borderRadius: "4px",
    border: "1px solid #D2E9E3",
    padding: "10px",
    color: "#202124",
    fontSize: "14px",
    resize: "none",
    boxSizing: "border-box",
  },
};

export default Dashboard;