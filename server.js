// Import required modules
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Web3 } = require('web3');
const path = require('path');
const fs = require('fs');

// Set up Express app
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-vault-secret-key';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory database (replace with real DB in production)
const db = {
  users: [
    {
      id: 1,
      username: 'admin',
      // Hashed 'SecurePass123!'
      passwordHash: '$2b$10$l2NeDTc.UGNPcFVg00Mm0O7vgpLKT6jDlRs3XnP1AgRRZE0Aj1pjG',
      role: 'Administrator',
      lastLogin: null
    },
    {
      id: 2,
      username: 'auditor',
      // Hashed 'Audit@2023'
      passwordHash: '$2b$10$v9Yzr5DkrSOL/WJLQb.BXuyS6uKvfGzzraCYcJjBOyeP3iONcBsUm',
      role: 'Auditor',
      lastLogin: new Date(Date.now() - 7200000).toISOString() // 2 hours ago
    }
  ],
  threats: [
    {
      id: 1,
      time: "2023-04-10 14:30:22",
      ip: "185.143.223.67",
      type: "SQL Injection",
      endpoint: "/api/users",
      risk: "Critical"
    },
    {
      id: 2,
      time: "2023-04-10 13:45:11",
      ip: "91.234.108.22",
      type: "XSS Attempt",
      endpoint: "/contact",
      risk: "High"
    },
    {
      id: 3,
      time: "2023-04-10 12:18:05",
      ip: "192.168.1.105",
      type: "Brute Force",
      endpoint: "/admin/login",
      risk: "High"
    }
  ],
  bannedIPs: [
    {
      ip: "185.143.223.67",
      date: "2023-04-10",
      reason: "SQL Injection attempt"
    },
    {
      ip: "91.234.108.22",
      date: "2023-04-09",
      reason: "Multiple XSS attempts"
    }
  ],
  backups: [
    {
      id: 1,
      timestamp: "2023-04-10 12:00:00",
      reason: "Scheduled backup",
      storageHash: "QmZ9z7aPqEMJhK6HZqT7a2b",
      size: "124 MB",
      status: "Completed"
    },
    {
      id: 2,
      timestamp: "2023-04-09 18:00:00",
      reason: "Before system update",
      storageHash: "QmX4pR8s2EqL3f1c",
      size: "118 MB",
      status: "Completed"
    },
    {
      id: 3,
      timestamp: "2023-04-08 09:30:00",
      reason: "Scheduled backup",
      storageHash: "QmP8y6TqW9e5d",
      size: "112 MB",
      status: "Completed"
    }
  ],
  blockchainBackups: [
    {
      hash: "QmZ9z7aPqEMJhK6HZqT7a2b",
      tx: "0x123f5678901234567890abcdef",
      timestamp: "2023-04-10 12:00",
      verified: true
    },
    {
      hash: "QmX4pR8s2EqL3f1c",
      tx: "0x456f1234567890abcdef12345",
      timestamp: "2023-04-09 18:00",
      verified: true
    },
    {
      hash: "QmP8y6TqW9e5d",
      tx: "0x789f5678901234567890abcdef",
      timestamp: "2023-04-08 09:30",
      verified: false
    }
  ],
  systemStatus: {
    status: "Operational",
    honeypotActive: true,
    metrics: {
      cpu: 24,
      memory: 38,
      disk: 15,
      uptime: 99.98
    }
  }
};

// Blockchain configuration
const web3 = new Web3(process.env.WEB3_PROVIDER || 'http://localhost:8545');
const contractABI = [
  {
    "inputs": [
      { "internalType": "string", "name": "ipfsHash", "type": "string" },
      { "internalType": "address", "name": "initiator", "type": "address" }
    ],
    "name": "logBackup",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      { "internalType": "string", "name": "ipfsHash", "type": "string" }
    ],
    "name": "verifyBackup",
    "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
    "stateMutability": "view",
    "type": "function"
  }
];
const contractAddress = process.env.CONTRACT_ADDRESS || "0xAb5801a7D398351b8bE11C439e05C5b3259aec9B";
let contract;

try {
  contract = new web3.eth.Contract(contractABI, contractAddress);
} catch (error) {
  console.log("Contract initialization failed:", error.message);
}

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Authentication required' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = db.users.find(u => u.username === username);
  if (!user) {
    // Log failed attempt
    logFailedLoginAttempt(username, req.ip);
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  
  try {
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      // Log failed attempt
      logFailedLoginAttempt(username, req.ip);
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    // Update last login
    user.lastLogin = new Date().toISOString();
    
    // Generate token
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    
    return res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Dashboard data routes
app.get('/api/dashboard/overview', authenticateToken, (req, res) => {
  const stats = {
    totalUsers: 1248,
    activeThreats: db.threats.length,
    systemUptime: db.systemStatus.metrics.uptime,
    blockchainSync: 100,
    systemHealth: {
      cpu: db.systemStatus.metrics.cpu,
      memory: db.systemStatus.metrics.memory,
      disk: db.systemStatus.metrics.disk,
      status: db.systemStatus.status
    },
    users: db.users.map(u => ({
      username: u.username,
      role: u.role,
      lastLogin: u.lastLogin,
      status: 'Active'
    }))
  };
  
  res.json(stats);
});

// Threat management routes
app.get('/api/threats', authenticateToken, (req, res) => {
  res.json(db.threats);
});

app.post('/api/threats/ban', authenticateToken, (req, res) => {
  const { ip, reason } = req.body;
  
  // Check if IP is already banned
  if (db.bannedIPs.some(b => b.ip === ip)) {
    return res.status(400).json({ message: 'IP is already banned' });
  }
  
  // Add to banned IPs
  const newBan = {
    ip,
    date: new Date().toISOString().split('T')[0],
    reason
  };
  
  db.bannedIPs.push(newBan);
  res.json({ message: 'IP banned successfully', ban: newBan });
});

app.get('/api/threats/banned', authenticateToken, (req, res) => {
  res.json(db.bannedIPs);
});

app.delete('/api/threats/banned/:ip', authenticateToken, (req, res) => {
  const ip = req.params.ip;
  const initialLength = db.bannedIPs.length;
  
  db.bannedIPs = db.bannedIPs.filter(b => b.ip !== ip);
  
  if (db.bannedIPs.length < initialLength) {
    res.json({ message: 'IP unbanned successfully' });
  } else {
    res.status(404).json({ message: 'IP not found in banned list' });
  }
});

// Backup management routes
app.get('/api/backups', authenticateToken, (req, res) => {
  res.json(db.backups);
});

app.post('/api/backups/create', authenticateToken, async (req, res) => {
  const { reason } = req.body;
  
  try {
    // Simulate backup creation (in a real app, this would be more complex)
    const cid = "Qm" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const size = Math.floor(Math.random() * 100) + 50;
    
    const newBackup = {
      id: db.backups.length + 1,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      reason: reason || 'Manual backup',
      storageHash: cid,
      size: size + " MB",
      status: "Completed"
    };
    
    db.backups.unshift(newBackup);
    
    res.json({ 
      message: 'Backup created successfully',
      backup: newBackup
    });
  } catch (error) {
    console.error("Backup creation error:", error);
    res.status(500).json({ message: 'Backup creation failed', error: error.message });
  }
});

app.post('/api/backups/restore/:hash', authenticateToken, (req, res) => {
  const hash = req.params.hash;
  
  // Verify backup exists
  const backup = db.backups.find(b => b.storageHash === hash);
  if (!backup) {
    return res.status(404).json({ message: 'Backup not found' });
  }
  
  // Simulate restore process (in a real app, this would be more complex)
  setTimeout(() => {
    res.json({ message: 'Restore completed successfully', backup });
  }, 1000);
});

// Blockchain routes
app.get('/api/blockchain/backups', authenticateToken, (req, res) => {
  res.json(db.blockchainBackups);
});

app.post('/api/blockchain/log-backup', authenticateToken, async (req, res) => {
  const { hash, walletAddress } = req.body;
  
  if (!hash || !walletAddress) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }
  
  try {
    // In a real implementation, this would call the smart contract
    // For demo, we'll simulate a blockchain transaction
    const tx = "0x" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    
    const newBlockchainBackup = {
      hash,
      tx,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 16),
      verified: true
    };
    
    db.blockchainBackups.unshift(newBlockchainBackup);
    
    res.json({ 
      message: 'Backup logged to blockchain',
      tx,
      backup: newBlockchainBackup
    });
  } catch (error) {
    console.error("Blockchain logging error:", error);
    res.status(500).json({ message: 'Blockchain logging failed', error: error.message });
  }
});

app.post('/api/blockchain/verify-backup/:hash', authenticateToken, async (req, res) => {
  const hash = req.params.hash;
  
  try {
    // In a real implementation, this would call the smart contract
    // For demo, we'll simulate verification
    const backupIndex = db.blockchainBackups.findIndex(b => b.hash === hash);
    if (backupIndex === -1) {
      return res.status(404).json({ message: 'Backup not found on blockchain' });
    }
    
    // Update verification status (simulate contract call)
    db.blockchainBackups[backupIndex].verified = true;
    
    res.json({
      message: 'Backup verified successfully',
      hash,
      verified: true
    });
  } catch (error) {
    console.error("Verification error:", error);
    res.status(500).json({ message: 'Verification failed', error: error.message });
  }
});

// System management routes
app.get('/api/system/status', authenticateToken, (req, res) => {
  res.json(db.systemStatus);
});

app.post('/api/system/wipe', authenticateToken, async (req, res) => {
  const { walletAddress, backupCID } = req.body;
  
  if (!walletAddress || !backupCID) {
    return res.status(400).json({ message: 'Missing required parameters' });
  }
  
  try {
    // In a real implementation, this would actually wipe sensitive data
    // and verify the blockchain backup was successful
    
    // For demo, we'll just update the system status
    db.systemStatus.status = "Recovery Mode";
    db.systemStatus.honeypotActive = true;
    
    // Simulate a delay for the wipe process
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    res.json({
      message: 'Emergency wipe completed',
      status: db.systemStatus.status,
      backupCID
    });
  } catch (error) {
    console.error("Wipe error:", error);
    res.status(500).json({ message: 'Emergency wipe failed', error: error.message });
  }
});

// Helper functions
function logFailedLoginAttempt(username, ip) {
  const threat = {
    id: db.threats.length + 1,
    time: new Date().toISOString().replace('T', ' ').substring(0, 19),
    ip: ip || "192.168." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255),
    type: "Brute Force Attempt",
    endpoint: "/api/auth/login",
    risk: "High"
  };
  
  db.threats.unshift(threat);
  
  // Check if we should ban this IP (3+ failed attempts)
  const attemptsFromIP = db.threats.filter(t => t.ip === threat.ip && t.type.includes("Brute Force")).length;
  if (attemptsFromIP >= 3 && !db.bannedIPs.some(b => b.ip === threat.ip)) {
    db.bannedIPs.push({
      ip: threat.ip,
      date: new Date().toISOString().split('T')[0],
      reason: "Multiple failed login attempts"
    });
  }
}

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`SentinelVault backend running on port ${PORT}`);
});

module.exports = app;