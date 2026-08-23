import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Box, Typography, LinearProgress, Button, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import 'chart.js/auto';
import { Bar } from 'react-chartjs-2';
import { useAuth } from '../App';
import * as api from '../api';

export default function JobStatusPage() {
  const { jobId } = useParams();
  const { token } = useAuth();
  const [job, setJob] = useState(null);
  const [findings, setFindings] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [exportUrl, setExportUrl] = useState(null);
  const [loading, setLoading] = useState(true);

  // Poll job status until completed/failed
  useEffect(() => {
    let interval;
    async function fetchStatus() {
      try {
        const data = await api.getJob(jobId, token);
        setJob(data);
        if (data.status === 'completed') {
          clearInterval(interval);
          // Fetch findings and metrics
          const f = await api.getFindings(jobId, token);
          setFindings(f);
          try {
            const m = await api.getMetrics(jobId, token);
            setMetrics(m);
          } catch (err) {
            // metrics may not be available
          }
          setLoading(false);
        } else if (data.status === 'failed') {
          clearInterval(interval);
          setLoading(false);
        }
      } catch (err) {
        clearInterval(interval);
      }
    }
    fetchStatus();
    interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [jobId, token]);

  const handleExport = async () => {
    try {
      const res = await api.exportJob(jobId, token);
      setExportUrl(res.download_url);
    } catch (err) {
      console.error(err);
    }
  };

  // Prepare chart data (count by severity)
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
  const chartData = {
    labels: Object.keys(severityCounts),
    datasets: [
      {
        label: 'Findings by severity',
        data: Object.values(severityCounts),
        backgroundColor: 'rgba(54, 162, 235, 0.6)',
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1,
      },
    ],
  };

  return (
    <Box p={4}>
      <Typography variant="h5" gutterBottom>Job #{jobId} Status</Typography>
      {job && (
        <Typography>Status: {job.status} {job.progress && job.status !== 'completed' && `( ${Math.round(job.progress * 100)}% )`}</Typography>
      )}
      {job && job.status !== 'completed' && job.status !== 'failed' && (
        <Box sx={{ width: '100%', mt: 2 }}>
          <LinearProgress variant="determinate" value={job.progress * 100} />
        </Box>
      )}
      {!loading && job?.status === 'completed' && (
        <>
          <Box mt={4}>
            <Typography variant="h6">Metrics</Typography>
            {metrics ? (
              <TableContainer component={Paper} sx={{ maxWidth: 500 }}>
                <Table size="small">
                  <TableBody>
                    <TableRow>
                      <TableCell>k-anonymity</TableCell>
                      <TableCell>{metrics.k_anonymity ?? 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>l-diversity</TableCell>
                      <TableCell>{metrics.l_diversity ?? 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>t-closeness</TableCell>
                      <TableCell>{metrics.t_closeness ?? 'N/A'}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Typography>No metrics computed for this job.</Typography>
            )}
          </Box>
          <Box mt={4}>
            <Typography variant="h6" gutterBottom>Findings</Typography>
            {findings.length === 0 ? (
              <Typography>No sensitive data detected.</Typography>
            ) : (
              <>
                <Box sx={{ height: 240 }}>
                  <Bar data={chartData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }} />
                </Box>
                <TableContainer component={Paper} sx={{ maxHeight: 300, mt: 2 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>#</TableCell>
                        <TableCell>Record</TableCell>
                        <TableCell>Column</TableCell>
                        <TableCell>Rule</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Confidence</TableCell>
                        <TableCell>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {findings.map((f, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{f.id}</TableCell>
                          <TableCell>{f.record_index}</TableCell>
                          <TableCell>{f.column_name}</TableCell>
                          <TableCell>{f.rule_id}</TableCell>
                          <TableCell>{f.severity}</TableCell>
                          <TableCell>{f.confidence.toFixed(2)}</TableCell>
                          <TableCell>{f.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </>
            )}
          </Box>
          <Box mt={4}>
            {!exportUrl && <Button variant="contained" onClick={handleExport}>Export Sanitised CSV</Button>}
            {exportUrl && <a href={exportUrl} target="_blank" rel="noreferrer">Download Sanitised CSV</a>}
          </Box>
        </>
      )}
      {!loading && job?.status === 'failed' && (
        <Typography color="error" mt={4}>Job failed: {job.error_message}</Typography>
      )}
    </Box>
  );
}