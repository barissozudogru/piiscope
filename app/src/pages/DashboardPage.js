import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Typography, Button, TableContainer, Table, TableHead, TableRow, TableCell, TableBody, Paper, Chip } from '@mui/material';
import 'chart.js/auto';
import { Bar } from 'react-chartjs-2';
import { useAuth } from '../App';
import * as api from '../api';

export default function DashboardPage() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [jobs, setJobs] = useState([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getJobs(token);
        setJobs(data);
      } catch (err) {
        console.error(err);
      }
    }
    load();
  }, [token]);

  // Compute counts by status
  const statusCounts = jobs.reduce((acc, job) => {
    acc[job.status] = (acc[job.status] || 0) + 1;
    return acc;
  }, {});

  const chartData = {
    labels: Object.keys(statusCounts),
    datasets: [
      {
        label: 'Jobs by status',
        data: Object.values(statusCounts),
        backgroundColor: 'rgba(255, 99, 132, 0.6)',
        borderColor: 'rgba(255, 99, 132, 1)',
        borderWidth: 1,
      },
    ],
  };

  return (
    <Box p={4}>
      <Typography variant="h5" gutterBottom>Dashboard</Typography>
      <Button variant="contained" onClick={() => navigate('/upload')}>New Scan</Button>
      <Box mt={4}>
        <Box sx={{ height: 240 }}>
          <Bar data={chartData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }} />
        </Box>
      </Box>
      <Box mt={4}>
        <Typography variant="h6">Recent Jobs</Typography>
        {jobs.length === 0 ? (
          <Typography>No jobs yet.</Typography>
        ) : (
          <TableContainer component={Paper} sx={{ maxHeight: 300 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>File Name</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Progress</TableCell>
                  <TableCell>Started At</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {jobs.map((job) => (
                  <TableRow key={job.id} hover onClick={() => navigate(`/jobs/${job.id}`)} style={{ cursor: 'pointer' }}>
                    <TableCell>{job.id}</TableCell>
                    <TableCell>{job.file_name}</TableCell>
                    <TableCell>
                      <Chip label={job.status} color={job.status === 'completed' ? 'success' : job.status === 'running' ? 'warning' : job.status === 'failed' ? 'error' : 'default'} size="small" />
                    </TableCell>
                    <TableCell>{job.progress ? `${Math.round(job.progress * 100)}%` : '-'}</TableCell>
                    <TableCell>{job.started_at ? new Date(job.started_at).toLocaleString() : '-'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Box>
    </Box>
  );
}