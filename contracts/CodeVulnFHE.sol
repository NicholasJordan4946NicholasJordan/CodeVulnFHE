// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FHE, euint32, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract CodeVulnFHE is SepoliaConfig {
    // Struct for encrypted code submission
    struct EncryptedCode {
        uint256 id;
        address owner;
        euint32 encryptedData; // Encrypted source code
        uint256 timestamp;
        bool analyzed;
    }
    
    // Struct for vulnerability pattern
    struct VulnerabilityPattern {
        uint256 id;
        euint32 encryptedPattern; // Encrypted vulnerability pattern
        string description;
        uint256 severity;
    }
    
    // Struct for encrypted vulnerability report
    struct EncryptedReport {
        uint256 id;
        uint256 codeId;
        euint32 encryptedFindings; // Encrypted vulnerability findings
        uint256 timestamp;
    }
    
    // Contract state
    uint256 public codeCount;
    uint256 public patternCount;
    uint256 public reportCount;
    
    mapping(uint256 => EncryptedCode) public encryptedCodes;
    mapping(uint256 => VulnerabilityPattern) public vulnerabilityPatterns;
    mapping(uint256 => EncryptedReport) public encryptedReports;
    mapping(address => uint256[]) public userSubmissions;
    mapping(uint256 => uint256[]) public codeReports;
    
    // Events
    event CodeUploaded(uint256 indexed id, address indexed owner, uint256 timestamp);
    event PatternAdded(uint256 indexed id, string description, uint256 severity);
    event AnalysisCompleted(uint256 indexed reportId, uint256 codeId);
    event ReportDecrypted(uint256 indexed reportId);
    
    // Modifier to ensure only code owner can access
    modifier onlyCodeOwner(uint256 codeId) {
        require(encryptedCodes[codeId].owner == msg.sender, "Not code owner");
        _;
    }
    
    /// @notice Add a new vulnerability pattern
    function addVulnerabilityPattern(
        euint32 encryptedPattern, 
        string memory description,
        uint256 severity
    ) public {
        patternCount += 1;
        uint256 newId = patternCount;
        
        vulnerabilityPatterns[newId] = VulnerabilityPattern({
            id: newId,
            encryptedPattern: encryptedPattern,
            description: description,
            severity: severity
        });
        
        emit PatternAdded(newId, description, severity);
    }
    
    /// @notice Upload encrypted source code for analysis
    function uploadEncryptedCode(euint32 encryptedData) public {
        codeCount += 1;
        uint256 newId = codeCount;
        
        encryptedCodes[newId] = EncryptedCode({
            id: newId,
            owner: msg.sender,
            encryptedData: encryptedData,
            timestamp: block.timestamp,
            analyzed: false
        });
        
        userSubmissions[msg.sender].push(newId);
        emit CodeUploaded(newId, msg.sender, block.timestamp);
    }
    
    /// @notice Analyze code for vulnerabilities using FHE
    function analyzeCode(uint256 codeId) public onlyCodeOwner(codeId) {
        EncryptedCode storage code = encryptedCodes[codeId];
        require(!code.analyzed, "Code already analyzed");
        
        // Initialize findings (in real implementation, this would be more complex)
        euint32 findings = FHE.asEuint32(0);
        
        // Check against all vulnerability patterns
        for (uint256 i = 1; i <= patternCount; i++) {
            VulnerabilityPattern storage pattern = vulnerabilityPatterns[i];
            
            // Simulate pattern matching with FHE operations
            ebool match = FHE.eq(code.encryptedData, pattern.encryptedPattern);
            
            // If match found, update findings
            findings = FHE.add(
                findings, 
                FHE.select(match, FHE.asEuint32(pattern.severity), FHE.asEuint32(0))
            );
        }
        
        // Create encrypted report
        reportCount += 1;
        uint256 reportId = reportCount;
        
        encryptedReports[reportId] = EncryptedReport({
            id: reportId,
            codeId: codeId,
            encryptedFindings: findings,
            timestamp: block.timestamp
        });
        
        codeReports[codeId].push(reportId);
        code.analyzed = true;
        
        emit AnalysisCompleted(reportId, codeId);
    }
    
    /// @notice Request decryption of vulnerability report
    function requestReportDecryption(uint256 reportId) public {
        EncryptedReport storage report = encryptedReports[reportId];
        require(report.id != 0, "Invalid report ID");
        
        // Verify caller owns the code
        require(
            encryptedCodes[report.codeId].owner == msg.sender,
            "Not authorized to decrypt"
        );
        
        // Prepare encrypted data for decryption
        bytes32[] memory ciphertexts = new bytes32[](1);
        ciphertexts[0] = FHE.toBytes32(report.encryptedFindings);
        
        // Request decryption
        uint256 reqId = FHE.requestDecryption(ciphertexts, this.decryptReport.selector);
        codeReports[reqId] = [reportId]; // Store request ID mapping
    }
    
    /// @notice Callback for decrypted vulnerability report
    function decryptReport(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory proof
    ) public {
        uint256 reportId = codeReports[requestId][0];
        require(reportId != 0, "Invalid request");
        
        // Verify decryption proof
        FHE.checkSignatures(requestId, cleartexts, proof);
        
        // Process decrypted value
        uint32 findings = abi.decode(cleartexts, (uint32));
        
        // In a real implementation, we would store or process the decrypted findings
        // For this demo, we simply emit an event
        emit ReportDecrypted(reportId);
    }
    
    /// @notice Get user's code submissions
    function getUserSubmissions(address user) public view returns (uint256[] memory) {
        return userSubmissions[user];
    }
    
    /// @notice Get reports for a specific code submission
    function getCodeReports(uint256 codeId) public view returns (uint256[] memory) {
        return codeReports[codeId];
    }
    
    /// @notice Get vulnerability pattern details
    function getPatternDetails(uint256 patternId) public view returns (
        string memory description,
        uint256 severity
    ) {
        VulnerabilityPattern storage p = vulnerabilityPatterns[patternId];
        return (p.description, p.severity);
    }
}