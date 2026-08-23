import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { CssBaseline, AppBar, Toolbar, Typography, Button } from '@mui/material';
import LoginPage from './pages/LoginPage';
import UploadPage from './pages/UploadPage';
import JobStatusPage from './pages/JobStatusPage';
import DashboardPage from './pages/DashboardPage';

// Simple auth context to share token and user info
const AuthContext = createContext();

export function useAuth() {
  return useContext(AuthContext);
}

function PrivateRoute({ children }) {
  const { token } = useAuth();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token'));

  const login = (newToken) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
  };
  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      <CssBaseline />
      <Router>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              piiscope
            </Typography>
            {token && <Button color="inherit" onClick={logout}>Logout</Button>}
          </Toolbar>
        </AppBar>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/upload" element={<PrivateRoute><UploadPage /></PrivateRoute>} />
          <Route path="/jobs/:jobId" element={<PrivateRoute><JobStatusPage /></PrivateRoute>} />
          <Route path="/" element={<PrivateRoute><DashboardPage /></PrivateRoute>} />
        </Routes>
      </Router>
    </AuthContext.Provider>
  );
}