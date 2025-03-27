import React from "react";
import { Container, Typography, Box, Paper, List, ListItem, ListItemText } from "@mui/material";
import Link from 'next/link';

const HomePage = () => {
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
    <Container>
      <Box textAlign="center" mt={5}>
        <Typography variant="h2" component="h1" gutterBottom>
          Welcome to the Android Security Bulletin Dashboard
        </Typography>
        <Typography variant="h5" component="h2" gutterBottom>
          Your one-stop solution for monitoring and analyzing Android security vulnerabilities.
        </Typography>
        <Paper elevation={3} style={{ padding: '20px', marginTop: '20px' }}>
          <Typography variant="h6" component="h3" gutterBottom>
            About the Android Security Bulletin
          </Typography>
          <Typography variant="body1" paragraph>
            The Android Security Bulletin provides timely information about security vulnerabilities affecting Android devices. Each month, Google releases a new bulletin that includes details about the vulnerabilities, their severity, and the affected versions of Android.
          </Typography>
          <Typography variant="body1" paragraph>
            This dashboard allows you to easily monitor and analyze the latest security updates, helping you stay informed about potential risks and take necessary actions to protect your devices.
          </Typography>
        </Paper>
        <Paper elevation={3} style={{ padding: '20px', marginTop: '20px' }}>
          <Typography variant="h6" component="h3" gutterBottom>
            Monthly Updates
          </Typography>
          <List>
            {months.map((month) => (
              <ListItem key={month.id} button component={Link} href={`/dashboard/${month.id}`}>
                <ListItemText primary={month.title} />
              </ListItem>
            ))}
          </List>
        </Paper>
      </Box>
    </Container>
  );
};

export default HomePage;