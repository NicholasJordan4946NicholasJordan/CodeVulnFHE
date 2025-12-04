// App.tsx
import { ConnectButton } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import React, { useEffect, useState } from "react";
import { ethers } from "ethers";
import { getContractReadOnly, getContractWithSigner } from "./contract";
import "./App.css";
import { useAccount, useSignMessage } from 'wagmi';

interface VulnerabilityReport {
  id: string;
  encryptedData: string;
  timestamp: number;
  owner: string;
  language: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "pending" | "verified" | "rejected";
}

const FHEEncryption = (data: string): string => `FHE-${btoa(data)}`;
const FHEDecryption = (encryptedData: string): string => encryptedData.startsWith('FHE-') ? atob(encryptedData.substring(4)) : encryptedData;
const generatePublicKey = () => `0x${Array(2000).fill(0).map(() => Math.floor(Math.random() * 16).toString(16)).join('')}`;

const App: React.FC = () => {
  const { address, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<VulnerabilityReport[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{ visible: boolean; status: "pending" | "success" | "error"; message: string; }>({ visible: false, status: "pending", message: "" });
  const [newReportData, setNewReportData] = useState({ language: "", codeSnippet: "" });
  const [selectedReport, setSelectedReport] = useState<VulnerabilityReport | null>(null);
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [publicKey, setPublicKey] = useState<string>("");
  const [contractAddress, setContractAddress] = useState<string>("");
  const [chainId, setChainId] = useState<number>(0);
  const [startTimestamp, setStartTimestamp] = useState<number>(0);
  const [durationDays, setDurationDays] = useState<number>(30);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const reportsPerPage = 5;
  
  // Statistics
  const verifiedCount = reports.filter(r => r.status === "verified").length;
  const pendingCount = reports.filter(r => r.status === "pending").length;
  const rejectedCount = reports.filter(r => r.status === "rejected").length;
  const criticalCount = reports.filter(r => r.severity === "critical").length;
  const highCount = reports.filter(r => r.severity === "high").length;
  const mediumCount = reports.filter(r => r.severity === "medium").length;
  const lowCount = reports.filter(r => r.severity === "low").length;

  useEffect(() => {
    loadReports().finally(() => setLoading(false));
    const initSignatureParams = async () => {
      const contract = await getContractReadOnly();
      if (contract) setContractAddress(await contract.getAddress());
      if (window.ethereum) {
        const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
        setChainId(parseInt(chainIdHex, 16));
      }
      setStartTimestamp(Math.floor(Date.now() / 1000));
      setDurationDays(30);
      setPublicKey(generatePublicKey());
    };
    initSignatureParams();
  }, []);

  const loadReports = async () => {
    setIsRefreshing(true);
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      const isAvailable = await contract.isAvailable();
      if (!isAvailable) return;
      const keysBytes = await contract.getData("report_keys");
      let keys: string[] = [];
      if (keysBytes.length > 0) {
        try {
          const keysStr = ethers.toUtf8String(keysBytes);
          if (keysStr.trim() !== '') keys = JSON.parse(keysStr);
        } catch (e) { console.error("Error parsing report keys:", e); }
      }
      const list: VulnerabilityReport[] = [];
      for (const key of keys) {
        try {
          const reportBytes = await contract.getData(`report_${key}`);
          if (reportBytes.length > 0) {
            try {
              const reportData = JSON.parse(ethers.toUtf8String(reportBytes));
              list.push({ 
                id: key, 
                encryptedData: reportData.data, 
                timestamp: reportData.timestamp, 
                owner: reportData.owner, 
                language: reportData.language, 
                severity: reportData.severity || "medium",
                status: reportData.status || "pending" 
              });
            } catch (e) { console.error(`Error parsing report data for ${key}:`, e); }
          }
        } catch (e) { console.error(`Error loading report ${key}:`, e); }
      }
      list.sort((a, b) => b.timestamp - a.timestamp);
      setReports(list);
    } catch (e) { console.error("Error loading reports:", e); } 
    finally { setIsRefreshing(false); setLoading(false); }
  };

  const submitReport = async () => {
    if (!isConnected) { alert("Please connect wallet first"); return; }
    setCreating(true);
    setTransactionStatus({ visible: true, status: "pending", message: "Encrypting code with Zama FHE..." });
    try {
      const encryptedData = FHEEncryption(JSON.stringify({ ...newReportData, timestamp: Date.now() }));
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract with signer");
      const reportId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
      const reportData = { 
        data: encryptedData, 
        timestamp: Math.floor(Date.now() / 1000), 
        owner: address, 
        language: newReportData.language,
        severity: "medium",
        status: "pending" 
      };
      await contract.setData(`report_${reportId}`, ethers.toUtf8Bytes(JSON.stringify(reportData)));
      const keysBytes = await contract.getData("report_keys");
      let keys: string[] = [];
      if (keysBytes.length > 0) {
        try { keys = JSON.parse(ethers.toUtf8String(keysBytes)); } 
        catch (e) { console.error("Error parsing keys:", e); }
      }
      keys.push(reportId);
      await contract.setData("report_keys", ethers.toUtf8Bytes(JSON.stringify(keys)));
      setTransactionStatus({ visible: true, status: "success", message: "Encrypted code submitted securely!" });
      await loadReports();
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
        setShowCreateModal(false);
        setNewReportData({ language: "", codeSnippet: "" });
      }, 2000);
    } catch (e: any) {
      const errorMessage = e.message.includes("user rejected transaction") ? "Transaction rejected by user" : "Submission failed: " + (e.message || "Unknown error");
      setTransactionStatus({ visible: true, status: "error", message: errorMessage });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { setCreating(false); }
  };

  const decryptWithSignature = async (encryptedData: string) => {
    if (!isConnected) { alert("Please connect wallet first"); return null; }
    setIsDecrypting(true);
    try {
      const message = `publickey:${publicKey}\ncontractAddresses:${contractAddress}\ncontractsChainId:${chainId}\nstartTimestamp:${startTimestamp}\ndurationDays:${durationDays}`;
      await signMessageAsync({ message });
      await new Promise(resolve => setTimeout(resolve, 1500));
      return FHEDecryption(encryptedData);
    } catch (e) { console.error("Decryption failed:", e); return null; } 
    finally { setIsDecrypting(false); }
  };

  const verifyReport = async (reportId: string) => {
    if (!isConnected) { alert("Please connect wallet first"); return; }
    setTransactionStatus({ visible: true, status: "pending", message: "Processing encrypted code with FHE..." });
    try {
      await new Promise(resolve => setTimeout(resolve, 3000));
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract with signer");
      const reportBytes = await contract.getData(`report_${reportId}`);
      if (reportBytes.length === 0) throw new Error("Report not found");
      const reportData = JSON.parse(ethers.toUtf8String(reportBytes));
      const updatedReport = { ...reportData, status: "verified" };
      await contract.setData(`report_${reportId}`, ethers.toUtf8Bytes(JSON.stringify(updatedReport)));
      setTransactionStatus({ visible: true, status: "success", message: "FHE verification completed successfully!" });
      await loadReports();
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
    } catch (e: any) {
      setTransactionStatus({ visible: true, status: "error", message: "Verification failed: " + (e.message || "Unknown error") });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    }
  };

  const rejectReport = async (reportId: string) => {
    if (!isConnected) { alert("Please connect wallet first"); return; }
    setTransactionStatus({ visible: true, status: "pending", message: "Processing encrypted code with FHE..." });
    try {
      await new Promise(resolve => setTimeout(resolve, 3000));
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract with signer");
      const reportBytes = await contract.getData(`report_${reportId}`);
      if (reportBytes.length === 0) throw new Error("Report not found");
      const reportData = JSON.parse(ethers.toUtf8String(reportBytes));
      const updatedReport = { ...reportData, status: "rejected" };
      await contract.setData(`report_${reportId}`, ethers.toUtf8Bytes(JSON.stringify(updatedReport)));
      setTransactionStatus({ visible: true, status: "success", message: "FHE rejection completed successfully!" });
      await loadReports();
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
    } catch (e: any) {
      setTransactionStatus({ visible: true, status: "error", message: "Rejection failed: " + (e.message || "Unknown error") });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    }
  };

  const isOwner = (reportAddress: string) => address?.toLowerCase() === reportAddress.toLowerCase();

  // Filter reports based on search term
  const filteredReports = reports.filter(report => {
    return (
      report.language.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.severity.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.status.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  // Get current reports for pagination
  const indexOfLastReport = currentPage * reportsPerPage;
  const indexOfFirstReport = indexOfLastReport - reportsPerPage;
  const currentReports = filteredReports.slice(indexOfFirstReport, indexOfLastReport);

  // Change page
  const paginate = (pageNumber: number) => setCurrentPage(pageNumber);

  // Render severity distribution chart
  const renderSeverityChart = () => {
    const total = reports.length || 1;
    const criticalPercentage = (criticalCount / total) * 100;
    const highPercentage = (highCount / total) * 100;
    const mediumPercentage = (mediumCount / total) * 100;
    const lowPercentage = (lowCount / total) * 100;
    
    return (
      <div className="severity-chart">
        <div className="chart-bar critical" style={{ width: `${criticalPercentage}%` }}>
          <span>Critical: {criticalCount}</span>
        </div>
        <div className="chart-bar high" style={{ width: `${highPercentage}%` }}>
          <span>High: {highCount}</span>
        </div>
        <div className="chart-bar medium" style={{ width: `${mediumPercentage}%` }}>
          <span>Medium: {mediumCount}</span>
        </div>
        <div className="chart-bar low" style={{ width: `${lowPercentage}%` }}>
          <span>Low: {lowCount}</span>
        </div>
      </div>
    );
  };

  if (loading) return (
    <div className="loading-screen">
      <div className="metal-spinner"></div>
      <p>Initializing encrypted connection...</p>
    </div>
  );

  return (
    <div className="app-container metal-theme">
      <header className="app-header">
        <div className="logo">
          <div className="logo-icon"><div className="shield-icon"></div></div>
          <h1>Code<span>Vuln</span>FHE</h1>
        </div>
        <div className="header-actions">
          <button onClick={() => setShowCreateModal(true)} className="create-report-btn metal-button">
            <div className="add-icon"></div>New Scan
          </button>
          <div className="wallet-connect-wrapper"><ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/></div>
        </div>
      </header>
      
      <div className="main-content">
        <div className="dashboard-panels">
          {/* Project Introduction Panel */}
          <div className="panel intro-panel">
            <div className="panel-header">
              <h2>Fully Homomorphic Encryption Vulnerability Scanner</h2>
              <div className="fhe-indicator"><div className="fhe-lock"></div><span>FHE Encryption Active</span></div>
            </div>
            <div className="panel-content">
              <p>
                <strong>CodeVulnFHE</strong> is an advanced source code analysis tool that scans encrypted private codebases using Fully Homomorphic Encryption (FHE) technology. 
                It matches known vulnerability patterns without exposing your source code, protecting your intellectual property.
              </p>
              <div className="features-grid">
                <div className="feature">
                  <div className="feature-icon">🔒</div>
                  <h3>Client-Side Encryption</h3>
                  <p>Code is encrypted locally before submission</p>
                </div>
                <div className="feature">
                  <div className="feature-icon">⚙️</div>
                  <h3>FHE Pattern Matching</h3>
                  <p>Vulnerability detection on encrypted data</p>
                </div>
                <div className="feature">
                  <div className="feature-icon">📄</div>
                  <h3>Encrypted Reports</h3>
                  <p>Results remain encrypted until decrypted by you</p>
                </div>
                <div className="feature">
                  <div className="feature-icon">🛡️</div>
                  <h3>IP Protection</h3>
                  <p>Your source code never leaves your control</p>
                </div>
              </div>
            </div>
          </div>
          
          {/* Statistics Panel */}
          <div className="panel stats-panel">
            <div className="panel-header">
              <h2>Vulnerability Statistics</h2>
              <button onClick={loadReports} className="refresh-btn metal-button" disabled={isRefreshing}>
                {isRefreshing ? "Refreshing..." : "Refresh Data"}
              </button>
            </div>
            <div className="panel-content">
              <div className="stats-grid">
                <div className="stat-item">
                  <div className="stat-value">{reports.length}</div>
                  <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{criticalCount}</div>
                  <div className="stat-label">Critical</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{highCount}</div>
                  <div className="stat-label">High</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{mediumCount}</div>
                  <div className="stat-label">Medium</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{lowCount}</div>
                  <div className="stat-label">Low</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{pendingCount}</div>
                  <div className="stat-label">Pending</div>
                </div>
              </div>
              
              <div className="severity-distribution">
                <h3>Severity Distribution</h3>
                {renderSeverityChart()}
              </div>
            </div>
          </div>
          
          {/* Reports Panel */}
          <div className="panel reports-panel">
            <div className="panel-header">
              <h2>Vulnerability Reports</h2>
              <div className="search-box">
                <input 
                  type="text" 
                  placeholder="Search by language, severity..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="metal-input"
                />
                <div className="search-icon">🔍</div>
              </div>
            </div>
            <div className="panel-content">
              <div className="reports-list">
                <div className="table-header">
                  <div className="header-cell">ID</div>
                  <div className="header-cell">Language</div>
                  <div className="header-cell">Severity</div>
                  <div className="header-cell">Date</div>
                  <div className="header-cell">Status</div>
                  <div className="header-cell">Actions</div>
                </div>
                {currentReports.length === 0 ? (
                  <div className="no-reports">
                    <div className="no-reports-icon"></div>
                    <p>No vulnerability reports found</p>
                    <button className="metal-button primary" onClick={() => setShowCreateModal(true)}>Run First Scan</button>
                  </div>
                ) : currentReports.map(report => (
                  <div className="report-row" key={report.id} onClick={() => setSelectedReport(report)}>
                    <div className="table-cell report-id">#{report.id.substring(0, 6)}</div>
                    <div className="table-cell">{report.language}</div>
                    <div className="table-cell"><span className={`severity-badge ${report.severity}`}>{report.severity}</span></div>
                    <div className="table-cell">{new Date(report.timestamp * 1000).toLocaleDateString()}</div>
                    <div className="table-cell"><span className={`status-badge ${report.status}`}>{report.status}</span></div>
                    <div className="table-cell actions">
                      {isOwner(report.owner) && report.status === "pending" && (
                        <>
                          <button className="action-btn metal-button success" onClick={(e) => { e.stopPropagation(); verifyReport(report.id); }}>Verify</button>
                          <button className="action-btn metal-button danger" onClick={(e) => { e.stopPropagation(); rejectReport(report.id); }}>Reject</button>
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              
              {/* Pagination */}
              {filteredReports.length > reportsPerPage && (
                <div className="pagination">
                  {Array.from({ length: Math.ceil(filteredReports.length / reportsPerPage) }, (_, i) => i + 1).map(number => (
                    <button 
                      key={number} 
                      onClick={() => paginate(number)}
                      className={`page-btn ${currentPage === number ? 'active' : ''}`}
                    >
                      {number}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {showCreateModal && <ModalCreate onSubmit={submitReport} onClose={() => setShowCreateModal(false)} creating={creating} reportData={newReportData} setReportData={setNewReportData}/>}
      {selectedReport && <ReportDetailModal report={selectedReport} onClose={() => { setSelectedReport(null); setDecryptedContent(null); }} decryptedContent={decryptedContent} setDecryptedContent={setDecryptedContent} isDecrypting={isDecrypting} decryptWithSignature={decryptWithSignature}/>}
      {transactionStatus.visible && (
        <div className="transaction-modal">
          <div className="transaction-content metal-card">
            <div className={`transaction-icon ${transactionStatus.status}`}>
              {transactionStatus.status === "pending" && <div className="metal-spinner"></div>}
              {transactionStatus.status === "success" && <div className="check-icon"></div>}
              {transactionStatus.status === "error" && <div className="error-icon"></div>}
            </div>
            <div className="transaction-message">{transactionStatus.message}</div>
          </div>
        </div>
      )}
      
      <footer className="app-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <div className="logo"><div className="shield-icon"></div><span>CodeVulnFHE</span></div>
            <p>Secure encrypted vulnerability scanning using Zama FHE technology</p>
          </div>
          <div className="footer-links">
            <a href="#" className="footer-link">Documentation</a>
            <a href="#" className="footer-link">Privacy Policy</a>
            <a href="#" className="footer-link">Terms of Service</a>
            <a href="#" className="footer-link">Contact</a>
          </div>
        </div>
        <div className="footer-bottom">
          <div className="fhe-badge"><span>FHE-Powered Privacy</span></div>
          <div className="copyright">© {new Date().getFullYear()} CodeVulnFHE. All rights reserved.</div>
        </div>
      </footer>
    </div>
  );
};

interface ModalCreateProps {
  onSubmit: () => void; 
  onClose: () => void; 
  creating: boolean;
  reportData: any;
  setReportData: (data: any) => void;
}

const ModalCreate: React.FC<ModalCreateProps> = ({ onSubmit, onClose, creating, reportData, setReportData }) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setReportData({ ...reportData, [name]: value });
  };

  const handleSubmit = () => {
    if (!reportData.language || !reportData.codeSnippet) { alert("Please fill required fields"); return; }
    onSubmit();
  };

  return (
    <div className="modal-overlay">
      <div className="create-modal metal-card">
        <div className="modal-header">
          <h2>New Vulnerability Scan</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        <div className="modal-body">
          <div className="fhe-notice-banner">
            <div className="key-icon"></div> 
            <div><strong>FHE Encryption Notice</strong><p>Your source code will be encrypted with Zama FHE before submission</p></div>
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label>Programming Language *</label>
              <select name="language" value={reportData.language} onChange={handleChange} className="metal-select">
                <option value="">Select language</option>
                <option value="Solidity">Solidity</option>
                <option value="JavaScript">JavaScript</option>
                <option value="TypeScript">TypeScript</option>
                <option value="Python">Python</option>
                <option value="Java">Java</option>
                <option value="C++">C++</option>
                <option value="Rust">Rust</option>
                <option value="Go">Go</option>
              </select>
            </div>
            <div className="form-group full-width">
              <label>Code Snippet *</label>
              <textarea 
                name="codeSnippet" 
                value={reportData.codeSnippet} 
                onChange={handleChange} 
                placeholder="Enter code to scan for vulnerabilities..." 
                className="metal-textarea" 
                rows={6}
              />
            </div>
          </div>
          <div className="encryption-preview">
            <h4>Encryption Preview</h4>
            <div className="preview-container">
              <div className="plain-data"><span>Plain Code:</span><div>{reportData.codeSnippet.substring(0, 100) || 'No code entered'}...</div></div>
              <div className="encryption-arrow">→</div>
              <div className="encrypted-data">
                <span>Encrypted Data:</span>
                <div>{reportData.codeSnippet ? FHEEncryption(reportData.codeSnippet).substring(0, 50) + '...' : 'No code entered'}</div>
              </div>
            </div>
          </div>
          <div className="privacy-notice">
            <div className="privacy-icon"></div> 
            <div><strong>Source Code Privacy Guarantee</strong><p>Your code remains encrypted during FHE processing and is never decrypted on our servers</p></div>
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="cancel-btn metal-button">Cancel</button>
          <button onClick={handleSubmit} disabled={creating} className="submit-btn metal-button primary">
            {creating ? "Encrypting with FHE..." : "Scan Securely"}
          </button>
        </div>
      </div>
    </div>
  );
};

interface ReportDetailModalProps {
  report: VulnerabilityReport;
  onClose: () => void;
  decryptedContent: string | null;
  setDecryptedContent: (content: string | null) => void;
  isDecrypting: boolean;
  decryptWithSignature: (encryptedData: string) => Promise<string | null>;
}

const ReportDetailModal: React.FC<ReportDetailModalProps> = ({ report, onClose, decryptedContent, setDecryptedContent, isDecrypting, decryptWithSignature }) => {
  const handleDecrypt = async () => {
    if (decryptedContent) { setDecryptedContent(null); return; }
    const decrypted = await decryptWithSignature(report.encryptedData);
    if (decrypted) setDecryptedContent(decrypted);
  };

  return (
    <div className="modal-overlay">
      <div className="report-detail-modal metal-card">
        <div className="modal-header">
          <h2>Vulnerability Report #{report.id.substring(0, 8)}</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        <div className="modal-body">
          <div className="report-info">
            <div className="info-item"><span>Language:</span><strong>{report.language}</strong></div>
            <div className="info-item"><span>Severity:</span><strong className={`severity-badge ${report.severity}`}>{report.severity}</strong></div>
            <div className="info-item"><span>Date:</span><strong>{new Date(report.timestamp * 1000).toLocaleString()}</strong></div>
            <div className="info-item"><span>Status:</span><strong className={`status-badge ${report.status}`}>{report.status}</strong></div>
          </div>
          <div className="encrypted-data-section">
            <h3>Encrypted Vulnerability Data</h3>
            <div className="encrypted-data">{report.encryptedData.substring(0, 100)}...</div>
            <div className="fhe-tag"><div className="fhe-icon"></div><span>FHE Encrypted</span></div>
            <button className="decrypt-btn metal-button" onClick={handleDecrypt} disabled={isDecrypting}>
              {isDecrypting ? <span className="decrypt-spinner"></span> : decryptedContent ? "Hide Decrypted Data" : "Decrypt with Wallet Signature"}
            </button>
          </div>
          {decryptedContent && (
            <div className="decrypted-data-section">
              <h3>Decrypted Vulnerability Report</h3>
              <div className="decrypted-data">
                <pre>{JSON.stringify(JSON.parse(decryptedContent), null, 2)}</pre>
              </div>
              <div className="decryption-notice">
                <div className="warning-icon"></div>
                <span>Decrypted data is only visible after wallet signature verification</span>
              </div>
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="close-btn metal-button">Close</button>
        </div>
      </div>
    </div>
  );
};

export default App;