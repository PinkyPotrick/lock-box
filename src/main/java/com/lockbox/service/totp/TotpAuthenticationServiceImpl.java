package com.lockbox.service.totp;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.totp.TotpAuthenticationRequestDTO;
import com.lockbox.model.User;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.UserRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;

import jakarta.servlet.http.HttpSession;

@Service
public class TotpAuthenticationServiceImpl implements TotpAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(TotpAuthenticationServiceImpl.class);

    @Autowired
    private TemporarySessionService temporarySessionService;

    @Autowired
    private TotpService totpService;

    @Autowired
    private HttpSession httpSession;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Verifies TOTP code and completes user authentication
     * 
     * @param requestDTO - The TOTP authentication request containing code and session ID
     * @return A UserLoginResponseDTO with the session token and user credentials
     * @throws Exception If verification fails or user not found
     */
    @Override
    public boolean verifyTotpOnly(TotpAuthenticationRequestDTO requestDTO) throws Exception {

        // Check if TOTP verification is already in progress
        if (Boolean.TRUE.equals(httpSession.getAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS))) {
            throw new Exception("TOTP verification already in progress");
        }
        httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS, true);

        // Validate the temporary session
        String userId = temporarySessionService.validateTemporarySession(requestDTO.getSessionId());
        if (userId == null) {
            httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS, false);
            httpSession.invalidate(); // Invalidate session if session ID is invalid or expired
            logger.warn("TOTP verification attempt with invalid session ID");
            throw new Exception("Invalid or expired session");
        }

        // Verify the TOTP code
        boolean isValid = totpService.verifyTotpAuthentication(userId, requestDTO.getCode());
        if (!isValid) {
            httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS, false);
            logger.warn("TOTP verification failed - invalid code for user: {}", userId);
            throw new Exception("Invalid TOTP code");
        }

        // Remove the temporary session
        temporarySessionService.removeTemporarySession(requestDTO.getSessionId());

        // Get user data
        Optional<User> userOpt = userRepository.findById(userId);
        if (!userOpt.isPresent()) {
            httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS, false);
            logger.warn("TOTP verification failed - user not found: {}", userId);
            throw new Exception("User not found");
        }

        if (isValid) {
            // Mark TOTP as verified in session
            httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_VERIFIED, true);
            httpSession.setAttribute(AppConstants.HttpSessionAttributes.TOTP_IN_PROGRESS, false);

            // Log the successful TOTP authentication
            auditLogService.logUserAction(userId, ActionType.TOTP_VERIFICATION_SUCCESS, OperationType.READ,
                    LogLevel.INFO, userId, "TOTP Authentication", ActionStatus.SUCCESS, null,
                    "TOTP verification successful, authentication completed");
        }

        return isValid;
    }
}