package com.lockbox.blockchain.api;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.blockchain.dto.BlockchainCredentialDetailsDTO;
import com.lockbox.blockchain.service.BlockchainCredentialVerifier;
import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialMapper;
import com.lockbox.model.Credential;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.credential.CredentialServerEncryptionService;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

/**
 * Controller for blockchain-related administrative operations.
 */
@RestController
@RequestMapping("/api/admin/blockchain")
public class BlockchainController {

    private final Logger logger = LoggerFactory.getLogger(BlockchainController.class);

    @Autowired(required = false)
    private BlockchainCredentialVerifier blockchainVerifier;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private CredentialServerEncryptionService credentialServerEncryptionService;

    @Autowired
    private CredentialMapper credentialMapper;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private SecurityUtils securityUtils;

    @Value("${blockchain.feature.enabled:false}")
    private boolean blockchainFeatureEnabled;

    /**
     * Get detailed blockchain information about a credential. This endpoint is for administrative and demonstration
     * purposes.
     * 
     * @param id The credential ID
     * @return Blockchain details for the credential
     */
    @GetMapping("/credentials/{id}/details")
    public ResponseEntityDTO<BlockchainCredentialDetailsDTO> getBlockchainDetails(@PathVariable("id") String id) {
        try {
            // Ensure user is admin
            securityUtils.ensureAdmin();

            if (!blockchainFeatureEnabled || blockchainVerifier == null) {
                return ResponseEntityBuilder.handleErrorDTO(new IllegalStateException("Blockchain feature is disabled"),
                        "Blockchain feature is disabled");
            }

            String userId = securityUtils.getCurrentUserId();

            // Get credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                return ResponseEntityBuilder.handleErrorDTO(new Exception("Credential not found"),
                        "Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Decrypt credential for hash computation
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);
            CredentialDTO dto = credentialMapper.toDTO(decryptedCredential);

            // Get blockchain data
            BlockchainCredentialDetailsDTO details = new BlockchainCredentialDetailsDTO();
            details.setCredentialId(id);
            details.setVaultId(credential.getVaultId());
            details.setOwnerId(credential.getUserId());

            // Compute current hash
            String currentHash = blockchainVerifier.computeCredentialHash(dto);
            details.setCurrentHash(currentHash);

            try {
                // Get blockchain data
                String storedHash = blockchainVerifier.getCredentialHash(id);

                // The hash might be null if not found
                boolean hashExists = storedHash != null && !storedHash.isEmpty();
                details.setExistsOnBlockchain(hashExists);

                if (hashExists) {
                    details.setStoredHash(storedHash);
                    details.setVerified(currentHash.equals(storedHash));

                    // Get timestamp, which might also be null
                    BigInteger lastUpdatedTimestamp = blockchainVerifier.getLastUpdated(id);

                    if (lastUpdatedTimestamp != null && lastUpdatedTimestamp.longValue() > 0) {
                        details.setLastUpdated(
                                LocalDateTime.ofEpochSecond(lastUpdatedTimestamp.longValue(), 0, ZoneOffset.UTC));
                    }
                }

                // Add metadata about the hash (without exposing actual sensitive data)
                details.addMetadata("usernameLength", dto.getUsername() != null ? dto.getUsername().length() : 0);
                details.addMetadata("emailLength", dto.getEmail() != null ? dto.getEmail().length() : 0);
                details.addMetadata("passwordLength", dto.getPassword() != null ? dto.getPassword().length() : 0);
                details.addMetadata("passwordStrength", getPasswordStrength(dto.getPassword()));
                details.addMetadata("createdAt", dto.getCreatedAt());
                details.addMetadata("updatedAt", dto.getUpdatedAt());

                // Log the admin action
                auditLogService.logUserAction(userId, ActionType.ADMIN_BLOCKCHAIN_VERIFICATION, OperationType.READ,
                        LogLevel.INFO, id, "Blockchain Details", ActionStatus.SUCCESS, null,
                        "Admin retrieved blockchain details for credential: " + id);

                return new ResponseEntityBuilder<BlockchainCredentialDetailsDTO>().setData(details)
                        .setMessage("Blockchain details retrieved successfully").build();

            } catch (Exception e) {
                details.setExistsOnBlockchain(false);
                details.setErrorMessage("Error retrieving blockchain data: " + e.getMessage());

                logger.error("Error fetching blockchain data: {}", e.getMessage(), e);

                // Log the error
                auditLogService.logUserAction(userId, ActionType.ADMIN_BLOCKCHAIN_VERIFICATION, OperationType.READ,
                        LogLevel.ERROR, id, "Blockchain Details", ActionStatus.FAILURE, e.getMessage(),
                        "Failed to retrieve blockchain details for credential: " + id);

                return new ResponseEntityBuilder<BlockchainCredentialDetailsDTO>().setData(details)
                        .setMessage("Blockchain data unavailable").build();
            }
        } catch (Exception e) {
            logger.error("Error in blockchain details endpoint: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to retrieve blockchain details");
        }
    }

    /**
     * Get status information about blockchain integration.
     * 
     * @return Status details of the blockchain integration
     */
    @GetMapping("/status")
    public ResponseEntityDTO<Map<String, Object>> getBlockchainStatus() {
        try {
            // Ensure user is admin
            securityUtils.ensureAdmin();

            Map<String, Object> status = new HashMap<>();
            status.put("enabled", blockchainFeatureEnabled);

            if (!blockchainFeatureEnabled || blockchainVerifier == null) {
                status.put("active", false);
                status.put("message", "Blockchain feature is disabled");
                return new ResponseEntityBuilder<Map<String, Object>>().setData(status)
                        .setMessage("Blockchain status retrieved").build();
            }

            // Check connection to blockchain
            boolean connected = false;
            String connectionMessage = "";
            try {
                // Try to get the current block number as a connection test
                BigInteger blockNumber = blockchainVerifier.getBlockNumber();
                connected = true;
                connectionMessage = "Connected (current block: " + blockNumber + ")";
            } catch (Exception e) {
                connected = false;
                connectionMessage = "Connection error: " + e.getMessage();
            }

            status.put("active", connected);
            status.put("message", connectionMessage);

            // Log admin action
            String userId = securityUtils.getCurrentUserId();
            auditLogService.logUserAction(userId, ActionType.ADMIN_BLOCKCHAIN_VERIFICATION, OperationType.READ,
                    LogLevel.INFO, null, "Blockchain Status", ActionStatus.SUCCESS, null,
                    "Admin checked blockchain status");

            return new ResponseEntityBuilder<Map<String, Object>>().setData(status)
                    .setMessage("Blockchain status retrieved successfully").build();
        } catch (Exception e) {
            logger.error("Error checking blockchain status: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to retrieve blockchain status");
        }
    }

    /**
     * Records or updates a credential hash on the blockchain. This is primarily for: 1. Legacy credentials created
     * before blockchain was enabled 2. Re-recording credentials that fail verification
     * 
     * @param id The credential ID
     * @return Result of the operation
     */
    @PostMapping("/credentials/{id}/record")
    public ResponseEntityDTO<Map<String, Object>> recordCredentialOnBlockchain(@PathVariable("id") String id) {
        try {
            // Ensure user is admin
            securityUtils.ensureAdmin();

            if (!blockchainFeatureEnabled || blockchainVerifier == null) {
                return ResponseEntityBuilder.handleErrorDTO(new IllegalStateException("Blockchain feature is disabled"),
                        "Blockchain feature is disabled");
            }

            String userId = securityUtils.getCurrentUserId();

            // Get credential
            Optional<Credential> credentialOpt = credentialRepository.findById(id);
            if (!credentialOpt.isPresent()) {
                return ResponseEntityBuilder.handleErrorDTO(new Exception("Credential not found"),
                        "Credential not found");
            }

            Credential credential = credentialOpt.get();

            // Decrypt credential for hash computation
            Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);
            CredentialDTO dto = credentialMapper.toDTO(decryptedCredential);

            // Compute hash
            String credentialHash = blockchainVerifier.computeCredentialHash(dto);
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("credentialId", id);

            // Check if credential already exists on blockchain
            String existingHash = null;
            boolean alreadyExists = false;
            try {
                existingHash = blockchainVerifier.getCredentialHash(id);
                alreadyExists = existingHash != null && !existingHash.isEmpty();

                if (alreadyExists) {
                    responseData.put("existingHash", existingHash);
                    responseData.put("matches", credentialHash.equals(existingHash));
                }
            } catch (Exception e) {
                // Expected if credential doesn't exist yet
                logger.debug("Credential not found on blockchain, will create: {}", id);
            }

            responseData.put("alreadyExisted", alreadyExists);
            responseData.put("action", alreadyExists ? "updated" : "created");

            // Store on blockchain (even if it exists - this acts as an update)
            String txHash = blockchainVerifier.storeCredentialHash(id, credentialHash).get();
            responseData.put("transactionHash", txHash);
            responseData.put("hash", credentialHash);

            // Log action
            ActionType actionType = alreadyExists ? ActionType.ADMIN_BLOCKCHAIN_UPDATE
                    : ActionType.ADMIN_BLOCKCHAIN_RECORD;
            OperationType opType = alreadyExists ? OperationType.UPDATE : OperationType.WRITE;

            auditLogService.logUserAction(userId, actionType, opType, LogLevel.INFO, id, "Blockchain Record",
                    ActionStatus.SUCCESS, null, alreadyExists ? "Updated credential on blockchain: " + id
                            : "Recorded credential on blockchain: " + id);

            return new ResponseEntityBuilder<Map<String, Object>>().setData(responseData)
                    .setMessage(alreadyExists ? "Credential hash updated on blockchain"
                            : "Credential successfully recorded on blockchain")
                    .build();

        } catch (Exception e) {
            logger.error("Error in blockchain record endpoint: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to process blockchain record request");
        }
    }

    @PostMapping("/credentials/batch-record")
    public ResponseEntityDTO<Map<String, Object>> batchRecordCredentialsOnBlockchain(
            @RequestParam("ids") String idsList) {
        try {
            // Ensure user is admin
            securityUtils.ensureAdmin();

            if (!blockchainFeatureEnabled || blockchainVerifier == null) {
                return ResponseEntityBuilder.handleErrorDTO(new IllegalStateException("Blockchain feature is disabled"),
                        "Blockchain feature is disabled");
            }

            String userId = securityUtils.getCurrentUserId();

            // Parse the semicolon-separated list
            String[] ids = idsList.split(";");
            if (ids.length == 0) {
                return ResponseEntityBuilder.handleErrorDTO(new IllegalArgumentException("No credential IDs provided"),
                        "Please provide at least one credential ID");
            }

            logger.info("Starting batch blockchain recording for {} credentials", ids.length);

            // Track results
            Map<String, Object> responseData = new HashMap<>();
            Map<String, Object> results = new HashMap<>();
            List<String> successful = new ArrayList<>();
            List<String> failed = new ArrayList<>();
            List<String> notFound = new ArrayList<>();
            int existingCount = 0;
            int newCount = 0;

            // Process each credential
            for (String id : ids) {
                String trimmedId = id.trim();
                if (trimmedId.isEmpty())
                    continue;

                try {
                    Map<String, Object> credentialResult = new HashMap<>();

                    // Get credential
                    Optional<Credential> credentialOpt = credentialRepository.findById(trimmedId);
                    if (!credentialOpt.isPresent()) {
                        notFound.add(trimmedId);
                        credentialResult.put("status", "not_found");
                        results.put(trimmedId, credentialResult);
                        continue;
                    }

                    Credential credential = credentialOpt.get();

                    // Decrypt credential for hash computation
                    Credential decryptedCredential = credentialServerEncryptionService.decryptServerData(credential);
                    CredentialDTO dto = credentialMapper.toDTO(decryptedCredential);

                    // Compute hash
                    String credentialHash = blockchainVerifier.computeCredentialHash(dto);

                    // Check if credential already exists on blockchain
                    boolean alreadyExists = false;
                    try {
                        String existingHash = blockchainVerifier.getCredentialHash(trimmedId);
                        alreadyExists = existingHash != null && !existingHash.isEmpty();
                        credentialResult.put("existingHash", alreadyExists ? existingHash : null);

                        if (alreadyExists) {
                            credentialResult.put("matches", credentialHash.equals(existingHash));
                        }
                    } catch (Exception e) {
                        // Expected if credential doesn't exist yet
                        logger.debug("Credential not found on blockchain, will create: {}", trimmedId);
                    }

                    // Record action type
                    if (alreadyExists) {
                        existingCount++;
                    } else {
                        newCount++;
                    }

                    // Store on blockchain
                    String txHash = blockchainVerifier.storeCredentialHash(trimmedId, credentialHash).get();

                    // Update result
                    credentialResult.put("status", "success");
                    credentialResult.put("action", alreadyExists ? "updated" : "created");
                    credentialResult.put("transactionHash", txHash);
                    credentialResult.put("hash", credentialHash);

                    successful.add(trimmedId);
                    results.put(trimmedId, credentialResult);

                    // Log single action (for individual credential tracking)
                    ActionType actionType = alreadyExists ? ActionType.ADMIN_BLOCKCHAIN_UPDATE
                            : ActionType.ADMIN_BLOCKCHAIN_RECORD;
                    OperationType opType = alreadyExists ? OperationType.UPDATE : OperationType.WRITE;

                    auditLogService.logUserAction(userId, actionType, opType, LogLevel.INFO, trimmedId,
                            "Blockchain Record", ActionStatus.SUCCESS, null, "Batch operation: "
                                    + (alreadyExists ? "Updated" : "Recorded") + " credential on blockchain");

                } catch (Exception e) {
                    logger.error("Error recording credential {} to blockchain: {}", trimmedId, e.getMessage(), e);
                    Map<String, Object> credentialResult = new HashMap<>();
                    credentialResult.put("status", "error");
                    credentialResult.put("error", e.getMessage());
                    results.put(trimmedId, credentialResult);
                    failed.add(trimmedId);
                }
            }

            // Add summary data
            responseData.put("summary", Map.of("total", ids.length, "successful", successful.size(), "failed",
                    failed.size(), "notFound", notFound.size(), "existing", existingCount, "new", newCount));
            responseData.put("results", results);
            responseData.put("successfulIds", successful);
            responseData.put("failedIds", failed);
            responseData.put("notFoundIds", notFound);

            // Log batch action
            auditLogService.logUserAction(userId, ActionType.ADMIN_BLOCKCHAIN_RECORD, OperationType.WRITE,
                    LogLevel.INFO, null, "Blockchain Batch Record",
                    successful.size() > 0 ? ActionStatus.SUCCESS : ActionStatus.FAILURE,
                    failed.size() > 0 ? String.format("%d of %d failed", failed.size(), ids.length) : null,
                    String.format("Batch recorded %d of %d credentials to blockchain", successful.size(), ids.length));

            return new ResponseEntityBuilder<Map<String, Object>>().setData(responseData)
                    .setMessage(String.format("Batch recording completed: %d successful, %d failed, %d not found",
                            successful.size(), failed.size(), notFound.size()))
                    .build();

        } catch (Exception e) {
            logger.error("Error in blockchain batch record endpoint: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to process blockchain batch record request");
        }
    }

    /**
     * Calculate password strength without exposing the password. Returns a value from 0-10 indicating strength.
     */
    private int getPasswordStrength(String password) {
        if (password == null || password.isEmpty())
            return 0;

        int score = 0;

        // Length points
        if (password.length() >= 8)
            score++;
        if (password.length() >= 12)
            score++;
        if (password.length() >= 16)
            score++;

        // Character variety
        if (password.matches(".*[a-z].*"))
            score++;
        if (password.matches(".*[A-Z].*"))
            score++;
        if (password.matches(".*[0-9].*"))
            score++;
        if (password.matches(".*[^a-zA-Z0-9].*"))
            score++;

        return Math.min(10, score);
    }
}