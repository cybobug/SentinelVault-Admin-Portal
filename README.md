# SentinelVault Admin Portal

SentinelVault is a demonstration prototype of a high-security administrative portal. It features a complete frontend dashboard and a Node.js/Express backend that handles authentication, threat tracking, backup management, and simulated blockchain verifications.

## 🚀 Features

*   **Secure Authentication**: JWT-based login system for administrators and auditors.
*   **Real-time Dashboard**: Overview of system health, active threats, and user statistics.
*   **Threat Management**: Track security incidents (SQL Injections, XSS, Brute Force attempts) and automatically or manually ban malicious IP addresses.
*   **Backup & Restore**: Create and manage system backups with storage hashes.
*   **Blockchain Integration (Simulated)**: Log backup hashes to the blockchain for immutable verification using Web3.
*   **System Controls**: Includes emergency "Wipe" capabilities to simulate placing the system in Recovery Mode with active honeypots.

## 🛠️ Technology Stack

*   **Frontend**: HTML, CSS, JavaScript (Vanilla), Bootstrap 5.1
*   **Backend**: Node.js, Express.js
*   **Security**: bcrypt, jsonwebtoken (JWT)
*   **Web3**: web3.js for blockchain interactions

## 📦 Installation & Setup

1. **Clone the repository** (if you haven't already).
2. **Install Dependencies**:
   ```bash
   npm install
   ```
3. **Start the Server**:
   ```bash
   # For production
   npm start
   
   # For development (with hot-reloading)
   npm run dev
   ```
4. **Access the Portal**: Open your web browser and navigate to `http://localhost:3000`.

## 🧑‍💻 Usage (Demo Accounts)

You can log in to the portal using the following mock credentials:

*   **Administrator Account**:
    *   Username: `admin`
    *   Password: `SecurePass123!`
*   **Auditor Account**:
    *   Username: `auditor`
    *   Password: `Audit@2023`

## ⚠️ Important Notes

*   **Prototype Status**: This project is currently a prototype/demo.
*   **Mock Database**: It uses an in-memory database. Any changes made (banning IPs, creating backups, etc.) will be lost when the server is restarted.
*   **Simulated Web3**: The blockchain logging and verification features are simulated and do not actually interact with a live Ethereum/Web3 network by default.

## 📝 License

This project is open-source and available under the MIT License.
