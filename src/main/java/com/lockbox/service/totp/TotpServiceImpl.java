package com.lockbox.service.totp;

import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.lockbox.dto.totp.TotpSetupDTO;
import com.lockbox.model.User;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.UserRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.service.user.UserServerEncryptionService;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.AuthenticationErrors;
import com.lockbox.utils.EncryptionUtils;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

@Service
public class TotpServiceImpl implements TotpService {

    private static final Logger logger = LoggerFactory.getLogger(TotpServiceImpl.class);
    private static final String ISSUER = "LockBox";
    private static final int SECRET_SIZE = 32;
    private static final int TOTP_PERIOD = 30;
    private static final int TOTP_DIGITS = 6;

    // Rate limiting - track failed attempts
    private final Cache<String, Integer> failedAttempts = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES).build();

    // Temporarily store TOTP secrets during setup
    private final ConcurrentHashMap<String, String> pendingSecrets = new ConcurrentHashMap<>();

    @Value("${app.totp.time-drift-tolerance:1}")
    private int timeDriftTolerance;

    @Value("${app.totp.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private UserServerEncryptionService userServerEncryptionService;

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Generate a new TOTP secret for a user
     * 
     * @param userId The user ID
     * @return A TOTP setup object containing the secret and QR code URL
     * @throws Exception If an error occurs
     */
    @Override
    public TotpSetupDTO generateTotpSecret(String userId) throws Exception {
        logger.info("Generating TOTP secret for user: {}", userId);

        try {
            // Get the user
            Optional<User> encryptedUserOpt = userRepository.findById(userId);
            if (!encryptedUserOpt.isPresent()) {
                throw new Exception("User not found");
            }

            User encryptedUser = encryptedUserOpt.get();
            User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);

            // Check if TOTP is already enabled
            if (decryptedUser.isTotpEnabled()) {
                throw new Exception("2FA is already enabled for this user");
            }

            // Generate a new secret
            SecretGenerator secretGenerator = new DefaultSecretGenerator(SECRET_SIZE);
            String secret = secretGenerator.generate();

            // Store the secret temporarily until it's verified
            pendingSecrets.put(userId, secret);

            // Create QR code data
            String username = decryptedUser.getUsername();
            String email = decryptedUser.getEmail();
            String label = email != null ? email : username;

            QrData qrData = new QrData.Builder().issuer(ISSUER).label(label).secret(secret)
                    .algorithm(HashingAlgorithm.SHA1).digits(TOTP_DIGITS).period(TOTP_PERIOD).build();

            // Generate QR code URL
            QrGenerator qrGenerator = new ZxingPngQrGenerator();
            byte[] qrCodeBytes = qrGenerator.generate(qrData);
            String qrCodeBase64 = Base64.getEncoder().encodeToString(qrCodeBytes);
            String qrCodeUrl = "data:image/png;base64," + qrCodeBase64;

            // Format secret for manual entry (4 chars per group)
            String manualEntryKey = formatSecretForManualEntry(secret);

            // Create response object
            TotpSetupDTO setupDTO = new TotpSetupDTO();
            setupDTO.setSecret(secret);
            setupDTO.setQrCodeUrl(qrCodeUrl);
            setupDTO.setManualEntryKey(manualEntryKey);

            // Log the action
            auditLogService.logUserAction(userId, ActionType.TOTP_SETUP_INITIATED, OperationType.WRITE, LogLevel.INFO,
                    userId, "TOTP Setup", ActionStatus.SUCCESS, null, "TOTP setup initiated");

            return setupDTO;
        } catch (Exception e) {
            logger.error("Failed to generate TOTP secret: {}", e.getMessage());

            // Log the error
            auditLogService.logUserAction(userId, ActionType.TOTP_SETUP_INITIATED, OperationType.WRITE, LogLevel.ERROR,
                    userId, "TOTP Setup", ActionStatus.FAILURE, e.getMessage(), "Failed to initiate TOTP setup");

            throw new Exception("Failed to generate TOTP secret: " + e.getMessage());
        }
    }

    /**
     * Verify a TOTP code during setup
     * 
     * @param userId The user ID
     * @param code The TOTP code to verify
     * @return true if verification is successful, false otherwise
     * @throws Exception If an error occurs
     */
    @Override
    @Transactional
    public boolean verifyTotpSetup(String userId, String code) throws Exception {
        logger.info("Verifying TOTP setup for user: {}", userId);

        try {
            // Get the user
            Optional<User> encryptedUserOpt = userRepository.findById(userId);
            if (!encryptedUserOpt.isPresent()) {
                throw new Exception("User not found");
            }

            User encryptedUser = encryptedUserOpt.get();
            User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);

            // Check if TOTP is already enabled
            if (decryptedUser.isTotpEnabled()) {
                throw new Exception("2FA is already enabled for this user");
            }

            // Get the pending secret
            String secret = pendingSecrets.get(userId);
            if (secret == null) {
                throw new Exception("No pending TOTP setup found. Please initiate setup first.");
            }

            // Verify the code
            if (!verifyCode(secret, code)) {
                auditLogService.logUserAction(userId, ActionType.TOTP_SETUP_VERIFICATION, OperationType.READ,
                        LogLevel.WARNING, userId, "TOTP Setup", ActionStatus.FAILURE, "Invalid TOTP code",
                        "Failed to verify TOTP setup code");
                return false;
            }

            // Encrypt the TOTP secret using the same approach as other sensitive user data
            // String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey()); // TODO is this needed?
            // SecretKey aesKey = EncryptionUtils.generateAESKey(); // TODO is this needed?
            String userPublicKeyPem = decryptedUser.getPublicKey();

            // Encrypt the TOTP secret with RSA using the user's public key
            String encryptedSecret = genericEncryptionService.encryptDTOWithRSA(secret, String.class, userPublicKeyPem);

            // Update the user
            decryptedUser.setTotpEnabled(true);
            decryptedUser.setTotpSecret(encryptedSecret);

            // Re-encrypt the user data and save
            User updatedEncryptedUser = userServerEncryptionService.encryptServerData(decryptedUser);
            userRepository.save(updatedEncryptedUser);

            // Remove the pending secret
            pendingSecrets.remove(userId);

            // Log the successful setup
            auditLogService.logUserAction(userId, ActionType.TOTP_SETUP_COMPLETED, OperationType.UPDATE, LogLevel.INFO,
                    userId, "TOTP Setup", ActionStatus.SUCCESS, null, "TOTP setup successfully completed");

            return true;
        } catch (Exception e) {
            logger.error("Failed to verify TOTP setup: {}", e.getMessage());

            // Log the error
            auditLogService.logUserAction(userId, ActionType.TOTP_SETUP_VERIFICATION, OperationType.UPDATE,
                    LogLevel.ERROR, userId, "TOTP Setup", ActionStatus.FAILURE, e.getMessage(),
                    "Failed to verify TOTP setup");

            throw new Exception("Failed to verify TOTP setup: " + e.getMessage());
        }
    }

    /**
     * Disable TOTP for a user
     * 
     * @param userId The user ID
     * @return true if TOTP was successfully disabled
     * @throws Exception If an error occurs
     */
    @Override
    @Transactional
    public boolean disableTotp(String userId) throws Exception {
        logger.info("Disabling TOTP for user: {}", userId);

        try {
            // Get the user
            Optional<User> encryptedUserOpt = userRepository.findById(userId);
            if (!encryptedUserOpt.isPresent()) {
                throw new Exception("User not found");
            }

            User encryptedUser = encryptedUserOpt.get();
            User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);

            // Check if TOTP is enabled
            if (!decryptedUser.isTotpEnabled()) {
                throw new Exception("2FA is not enabled for this user");
            }

            // Disable TOTP
            decryptedUser.setTotpEnabled(false);
            decryptedUser.setTotpSecret(null);

            // Re-encrypt the user data and save
            User updatedEncryptedUser = userServerEncryptionService.encryptServerData(decryptedUser);
            userRepository.save(updatedEncryptedUser);

            // Log the action
            auditLogService.logUserAction(userId, ActionType.TOTP_DISABLED, OperationType.UPDATE, LogLevel.INFO, userId,
                    "TOTP Management", ActionStatus.SUCCESS, null, "TOTP 2FA disabled successfully");

            return true;
        } catch (Exception e) {
            logger.error("Failed to disable TOTP: {}", e.getMessage());

            // Log the error
            auditLogService.logUserAction(userId, ActionType.TOTP_DISABLED, OperationType.UPDATE, LogLevel.ERROR,
                    userId, "TOTP Management", ActionStatus.FAILURE, e.getMessage(), "Failed to disable TOTP 2FA");

            throw new Exception("Failed to disable TOTP: " + e.getMessage());
        }
    }

    /**
     * Verify a TOTP code during authentication
     * 
     * @param userId The user ID
     * @param code The TOTP code to verify
     * @return true if verification is successful, false otherwise
     * @throws Exception If an error occurs
     */
    @Override
    public boolean verifyTotpAuthentication(String userId, String code) throws Exception {
        logger.info("Verifying TOTP authentication for user: {}", userId);

        // Check rate limiting first
        Integer attempts = failedAttempts.getIfPresent(userId);
        if (attempts != null && attempts >= maxFailedAttempts) {
            logger.warn("Too many failed TOTP attempts for user: {}", userId);
            auditLogService.logUserAction(userId, ActionType.TOTP_VERIFICATION, OperationType.READ, LogLevel.WARNING,
                    userId, "TOTP Verification", ActionStatus.FAILURE, "Too many failed attempts",
                    "TOTP verification failed: rate limit exceeded");
            throw new Exception(AuthenticationErrors.TOO_MANY_FAILED_ATTEMPTS);
        }

        try {
            // Get the user
            Optional<User> encryptedUserOpt = userRepository.findById(userId);
            if (!encryptedUserOpt.isPresent()) {
                throw new Exception("User not found");
            }

            User encryptedUser = encryptedUserOpt.get();
            User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);

            // Check if TOTP is enabled
            if (!decryptedUser.isTotpEnabled()) {
                throw new Exception("2FA is not enabled for this user");
            }

            // Get the encrypted secret
            String encryptedSecret = decryptedUser.getTotpSecret();
            if (encryptedSecret == null) {
                throw new Exception("TOTP secret not found");
            }

            // Decrypt the secret
            String decryptedUserPrivateKey = getDecryptedPrivateKey(encryptedUser);
            String secret = genericEncryptionService.decryptDTOWithRSA(encryptedSecret, String.class,
                    decryptedUserPrivateKey);

            // Verify the code
            boolean isValid = verifyCode(secret, code);

            if (isValid) {
                // Clear failed attempts on success
                failedAttempts.invalidate(userId);

                // Log successful verification
                auditLogService.logUserAction(userId, ActionType.TOTP_VERIFICATION, OperationType.READ, LogLevel.INFO,
                        userId, "TOTP Verification", ActionStatus.SUCCESS, null, "TOTP code verified successfully");
            } else {
                // Increment failed attempts
                if (attempts == null) {
                    failedAttempts.put(userId, 1);
                } else {
                    failedAttempts.put(userId, attempts + 1);
                }

                // Log failed verification
                auditLogService.logUserAction(userId, ActionType.TOTP_VERIFICATION, OperationType.READ,
                        LogLevel.WARNING, userId, "TOTP Verification", ActionStatus.FAILURE, "Invalid TOTP code",
                        "TOTP verification failed: invalid code");
            }

            return isValid;
        } catch (Exception e) {
            logger.error("Failed to verify TOTP authentication: {}", e.getMessage());

            // Log the error
            auditLogService.logUserAction(userId, ActionType.TOTP_VERIFICATION, OperationType.READ, LogLevel.ERROR,
                    userId, "TOTP Verification", ActionStatus.FAILURE, e.getMessage(),
                    "TOTP verification failed: " + e.getMessage());

            throw new Exception("Failed to verify TOTP authentication: " + e.getMessage());
        }
    }

    // Helper methods

    /**
     * Verify a TOTP code against a secret
     */
    private boolean verifyCode(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, TOTP_DIGITS);
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        // Set time step tolerance to allow for clock drift
        ((DefaultCodeVerifier) verifier).setTimePeriod(TOTP_PERIOD);
        ((DefaultCodeVerifier) verifier).setAllowedTimePeriodDiscrepancy(timeDriftTolerance);

        return verifier.isValidCode(secret, code);
    }

    /**
     * Format a TOTP secret for manual entry (4 characters per group)
     */
    private String formatSecretForManualEntry(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "";
        }

        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < secret.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                formatted.append(" ");
            }
            formatted.append(secret.charAt(i));
        }

        return formatted.toString().trim();
    }

    /**
     * Get the decrypted private key for a user
     */
    private String getDecryptedPrivateKey(User encryptedUser) throws Exception {
        // Decrypt the AES key with the server's private key
        String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(encryptedUser.getAesKey());
        SecretKey aesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

        // Decrypt the private key with the AES key
        return genericEncryptionService.decryptStringWithAESCBC(encryptedUser.getPrivateKey(), aesKey);
    }
}