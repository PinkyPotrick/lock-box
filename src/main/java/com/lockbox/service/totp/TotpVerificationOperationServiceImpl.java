package com.lockbox.service.totp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;

import jakarta.servlet.http.HttpSession;

@Service
public class TotpVerificationOperationServiceImpl implements TotpVerificationOperationService {

    private static final Logger logger = LoggerFactory.getLogger(TotpVerificationOperationServiceImpl.class);

    @Value("${app.totp.operation-verification-minutes:5}")
    private int verificationValidityMinutes;

    @Autowired
    private TotpService totpService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private HttpSession httpSession;

    /**
     * Verify a TOTP code for sensitive operations
     * 
     * @param userId    The user ID
     * @param code      The TOTP code
     * @param operation Optional operation description
     * @return true if verification is successful
     * @throws Exception if verification fails
     */
    @Override
    public boolean verifyOperationTotp(String userId, String code, String operation) throws Exception {
        logger.info("Verifying TOTP for sensitive operation: {}", operation);

        // Verify the TOTP code
        boolean isValid = totpService.verifyTotpAuthentication(userId, code);

        if (!isValid) {
            logger.warn("Operation TOTP verification failed for user {}: invalid code", userId);
            return false;
        }

        // Store verification timestamp in session
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED, true);
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED_TIMESTAMP,
                System.currentTimeMillis());

        // Log the verification
        auditLogService.logUserAction(userId, ActionType.TOTP_OPERATION_VERIFICATION, OperationType.READ, LogLevel.INFO,
                null, "TOTP Operation Verification", ActionStatus.SUCCESS, null,
                "TOTP verified for sensitive operation: " + (operation != null ? operation : "unspecified"));

        return true;
    }

    /**
     * Check if the user has a valid TOTP verification for sensitive operations
     * 
     * @return true if a valid verification exists
     */
    @Override
    public boolean hasValidVerification() {
        // Check if TOTP has been verified
        Boolean verified = (Boolean) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED);

        if (verified == null || !verified) {
            return false;
        }

        // Check if verification is still valid (within time window)
        Long timestamp = (Long) httpSession
                .getAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED_TIMESTAMP);

        if (timestamp == null) {
            return false;
        }

        long currentTime = System.currentTimeMillis();
        long elapsedMinutes = (currentTime - timestamp) / 60000;

        return elapsedMinutes <= verificationValidityMinutes;
    }

    /**
     * Invalidate any existing TOTP verification
     */
    @Override
    public void invalidateVerification() {
        httpSession.removeAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED);
        httpSession.removeAttribute(AppConstants.HttpSessionAttributes.TOTP_OPERATION_VERIFIED_TIMESTAMP);
    }
}
