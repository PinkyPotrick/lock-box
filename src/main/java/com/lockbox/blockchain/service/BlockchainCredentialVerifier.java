package com.lockbox.blockchain.service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

import com.lockbox.blockchain.contract.CredentialVerifier;
import com.lockbox.blockchain.dto.CredentialVerificationResult;
import com.lockbox.dto.credential.CredentialDTO;

@Service
@ConditionalOnProperty(name = "blockchain.feature.enabled", havingValue = "true")
public class BlockchainCredentialVerifier {

    private static final Logger logger = LoggerFactory.getLogger(BlockchainCredentialVerifier.class);

    @Autowired
    private CredentialVerifier contract;

    @Value("${blockchain.feature.enabled:false}")
    private boolean blockchainFeatureEnabled;

    /**
     * Computes a secure hash of the credential information Note: We're careful not to include actual sensitive data in
     * the hash Instead we use metadata like length and patterns
     */
    public String computeCredentialHash(CredentialDTO credential) throws NoSuchAlgorithmException {
        if (credential == null) {
            throw new IllegalArgumentException("Credential cannot be null");
        }

        // Generate deterministic string for hashing that doesn't contain actual sensitive data
        // Only store metadata about the credential, not the credential itself
        StringBuilder dataToHash = new StringBuilder();
        dataToHash.append("id:").append(credential.getId()).append(";");
        dataToHash.append("vault:").append(credential.getVaultId()).append(";");
        dataToHash.append("domain:").append(credential.getDomainId()).append(";");

        // For sensitive fields, use length and pattern metadata, not actual values
        if (credential.getUsername() != null) {
            dataToHash.append("username_len:").append(credential.getUsername().length()).append(";");
        }
        if (credential.getEmail() != null) {
            dataToHash.append("email_len:").append(credential.getEmail().length()).append(";");
            dataToHash.append("email_has_@:").append(credential.getEmail().contains("@")).append(";");
        }
        if (credential.getPassword() != null) {
            dataToHash.append("password_len:").append(credential.getPassword().length()).append(";");
            dataToHash.append("password_complexity:").append(passwordComplexityScore(credential.getPassword()))
                    .append(";");
        }
        if (credential.getNotes() != null) {
            dataToHash.append("notes_len:").append(credential.getNotes().length()).append(";");
        }

        // Add category and favorite status which aren't sensitive
        dataToHash.append("category:").append(credential.getCategory()).append(";");
        dataToHash.append("favorite:").append(credential.isFavorite()).append(";");

        // Add timestamps
        if (credential.getCreatedAt() != null) {
            dataToHash.append("created:").append(credential.getCreatedAt().toEpochSecond(ZoneOffset.UTC)).append(";");
        }
        if (credential.getUpdatedAt() != null) {
            dataToHash.append("updated:").append(credential.getUpdatedAt().toEpochSecond(ZoneOffset.UTC)).append(";");
        }

        // Add deletion status
        dataToHash.append("deleted:").append(credential.isDeleted()).append(";");
        if (credential.isDeleted() && credential.getDeletedAt() != null) {
            dataToHash.append("deleted_at:").append(credential.getDeletedAt().toEpochSecond(ZoneOffset.UTC))
                    .append(";");
        }

        // Compute SHA-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(dataToHash.toString().getBytes(StandardCharsets.UTF_8));

        return bytesToHex(hashBytes);
    }

    /**
     * Stores a credential hash on the blockchain
     */
    public CompletableFuture<String> storeCredentialHash(String credentialId, String hash) {
        if (!blockchainFeatureEnabled) {
            logger.info("Blockchain feature disabled. Skipping hash storage for credential: {}", credentialId);
            return CompletableFuture.completedFuture("Blockchain feature disabled");
        }

        try {
            logger.info("Storing credential hash for ID: {}", credentialId);
            return contract.storeCredentialHash(credentialId, hash).thenApply(TransactionReceipt::getTransactionHash)
                    .exceptionally(ex -> {
                        logger.error("Error storing credential hash on blockchain: {}", ex.getMessage(), ex);
                        return "Error: " + ex.getMessage();
                    });
        } catch (Exception e) {
            logger.error("Exception when storing credential hash: {}", e.getMessage(), e);
            CompletableFuture<String> future = new CompletableFuture<>();
            future.completeExceptionally(e);
            return future;
        }
    }

    /**
     * Stores a credential hash on the blockchain and waits for the transaction to be mined
     * @param credentialId The credential ID
     * @param hash The hash to store
     * @return The transaction hash
     * @throws Exception If there's an error storing the hash
     */
    public String storeCredentialHashAndWait(String credentialId, String hash) throws Exception {
        if (!blockchainFeatureEnabled) {
            throw new IllegalStateException("Blockchain feature is disabled");
        }

        try {
            logger.info("Storing credential hash for ID: {} (synchronous)", credentialId);
            
            // Start the transaction and wait for it to complete
            CompletableFuture<TransactionReceipt> future = contract.storeCredentialHash(credentialId, hash);
            TransactionReceipt receipt = future.get(); // This blocks until the future completes
            
            if (receipt.isStatusOK()) {
                logger.info("Transaction mined successfully: {}", receipt.getTransactionHash());
                return receipt.getTransactionHash();
            } else {
                throw new RuntimeException("Transaction failed: " + receipt.getStatus());
            }
        } catch (Exception e) {
            logger.error("Error storing credential hash synchronously: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Verifies a credential against its stored hash on the blockchain
     */
    public CompletableFuture<CredentialVerificationResult> verifyCredential(CredentialDTO credential) {
        if (!blockchainFeatureEnabled) {
            logger.info("Blockchain feature disabled. Skipping verification for credential: {}", credential.getId());
            CredentialVerificationResult result = new CredentialVerificationResult(false, false, null, null);
            return CompletableFuture.completedFuture(result);
        }

        CompletableFuture<CredentialVerificationResult> resultFuture = new CompletableFuture<>();

        try {
            String credentialId = credential.getId();
            logger.info("Verifying credential with ID: {}", credentialId);

            // Compute current hash
            String currentHash = computeCredentialHash(credential);

            // Handle the contract call
            contract.getCredentialHash(credentialId).sendAsync().thenApply(storedHash -> {
                // Check if empty or null (credential not found in blockchain)
                boolean exists = storedHash != null && !storedHash.isEmpty();

                if (!exists) {
                    logger.info("Credential hash not found on blockchain for ID: {}", credentialId);
                    resultFuture.complete(new CredentialVerificationResult(false, false, null, null));
                    return null;
                }

                // If we have a hash, verify it matches
                contract.verifyCredentialHash(credentialId, currentHash).sendAsync().thenCompose(matches -> {
                    contract.getLastUpdated(credentialId).sendAsync().thenApply(timestamp -> {
                        LocalDateTime lastUpdated = null;
                        if (timestamp != null && timestamp.longValue() > 0) {
                            lastUpdated = LocalDateTime.ofEpochSecond(timestamp.longValue(), 0, ZoneOffset.UTC);
                        }

                        logger.info("Credential verification result: exists={}, matches={}", exists, matches);

                        resultFuture
                                .complete(new CredentialVerificationResult(exists, matches, storedHash, lastUpdated));
                        return matches;
                    }).exceptionally(ex -> {
                        logger.error("Error getting last updated timestamp: {}", ex.getMessage(), ex);
                        resultFuture.complete(new CredentialVerificationResult(exists, false, storedHash, null));
                        return false;
                    });
                    return null;
                }).exceptionally(ex -> {
                    logger.error("Error verifying credential hash: {}", ex.getMessage(), ex);
                    resultFuture.complete(new CredentialVerificationResult(exists, false, storedHash, null));
                    return null;
                });
                return null;
            }).exceptionally(ex -> {
                // Handle "Empty value (0x) returned from contract" error specifically
                if (ex.getCause() instanceof org.web3j.tx.exceptions.ContractCallException
                        && ex.getCause().getMessage().contains("Empty value (0x) returned from contract")) {
                    logger.info("No record found on blockchain for credential ID: {}", credentialId);
                    resultFuture.complete(new CredentialVerificationResult(false, false, null, null));
                } else {
                    logger.error("Error retrieving credential hash from blockchain: {}", ex.getMessage(), ex);
                    resultFuture.completeExceptionally(ex);
                }
                return null;
            });
        } catch (Exception e) {
            logger.error("Exception when verifying credential: {}", e.getMessage(), e);
            resultFuture.completeExceptionally(e);
        }

        return resultFuture;
    }

    /**
     * Gets the current block number from the blockchain. Used as a connectivity test.
     * 
     * @return Current block number
     * @throws Exception If there's an error connecting to the blockchain
     */
    public BigInteger getBlockNumber() throws Exception {
        if (!blockchainFeatureEnabled) {
            throw new IllegalStateException("Blockchain feature is disabled");
        }

        return contract.getWeb3j().ethBlockNumber().send().getBlockNumber();
    }

    /**
     * Gets the credential hash from blockchain without verification
     * 
     * @param credentialId The credential ID
     * @return The stored hash
     * @throws Exception If there's an error fetching from blockchain
     */
    public String getCredentialHash(String credentialId) throws Exception {
        if (!blockchainFeatureEnabled) {
            throw new IllegalStateException("Blockchain feature is disabled");
        }

        try {
            String result = contract.getCredentialHash(credentialId).send();
            // Check if result is empty or null
            if (result == null || result.isEmpty()) {
                return null; // Return null instead of throwing exception
            }
            return result;
        } catch (org.web3j.tx.exceptions.ContractCallException e) {
            // Check for the specific empty value exception
            if (e.getMessage() != null && e.getMessage().contains("Empty value (0x) returned from contract")) {
                logger.info("No hash found for credential ID: {}", credentialId);
                return null; // Return null for non-existing values
            }
            // Re-throw other types of exceptions
            logger.error("Error retrieving credential hash from blockchain: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Gets the last updated timestamp for a credential hash
     * 
     * @param credentialId The credential ID
     * @return The last updated timestamp as BigInteger, or null if not found
     * @throws Exception If there's an error fetching from blockchain (other than not found)
     */
    public BigInteger getLastUpdated(String credentialId) throws Exception {
        if (!blockchainFeatureEnabled) {
            throw new IllegalStateException("Blockchain feature is disabled");
        }

        try {
            BigInteger result = contract.getLastUpdated(credentialId).send();
            return result;
        } catch (org.web3j.tx.exceptions.ContractCallException e) {
            // Check for the specific empty value exception
            if (e.getMessage() != null && e.getMessage().contains("Empty value (0x) returned from contract")) {
                logger.info("No timestamp found for credential ID: {}", credentialId);
                return null; // Return null for non-existing values
            }
            // Re-throw other types of exceptions
            logger.error("Error retrieving last updated timestamp from blockchain: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Helper method to calculate password complexity score Returns a score between 0-10 based on password composition
     * This doesn't expose the password, just a score of its strength
     */
    private int passwordComplexityScore(String password) {
        if (password == null || password.isEmpty())
            return 0;

        int score = 0;

        // Length points (up to 3)
        if (password.length() >= 8)
            score++;
        if (password.length() >= 12)
            score++;
        if (password.length() >= 16)
            score++;

        // Character variety points
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

    /**
     * Helper method to convert byte array to hex string
     */
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}