package com.lockbox.security.interceptor;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.security.annotation.RequireTotpVerification;
import com.lockbox.service.totp.TotpVerificationOperationService;
import com.lockbox.service.user.UserServerEncryptionService;
import com.lockbox.utils.SecurityUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class TotpRequiredInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(TotpRequiredInterceptor.class);

    @Autowired
    private TotpVerificationOperationService totpOperationVerificationService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserServerEncryptionService userServerEncryptionService;

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Method method = handlerMethod.getMethod();

        // Check if the method requires TOTP verification
        RequireTotpVerification annotation = method.getAnnotation(RequireTotpVerification.class);
        if (annotation == null) {
            // Also check class-level annotation
            annotation = handlerMethod.getBeanType().getAnnotation(RequireTotpVerification.class);
            if (annotation == null) {
                // No annotation, no verification needed
                return true;
            }
        }

        try {
            // Get current user
            String userId = securityUtils.getCurrentUserId();
            Optional<User> userOpt = userRepository.findById(userId);

            if (!userOpt.isPresent()) {
                logger.warn("User not found for ID: {}", userId);
                sendErrorResponse(response, "User not found");
                return false;
            }

            User encryptedUser = userOpt.get();
            User user = userServerEncryptionService.decryptServerData(encryptedUser);

            // If user doesn't have TOTP enabled, skip verification
            if (!user.isTotpEnabled()) {
                logger.debug("User {} doesn't have TOTP enabled, skipping verification", userId);
                return true;
            }

            // Check if user has a valid TOTP verification
            if (!totpOperationVerificationService.hasValidVerification()) {
                logger.warn("TOTP verification required for user {} accessing {}", userId, request.getRequestURI());
                sendTotpRequiredResponse(response);
                return false;
            }

            return true;

        } catch (Exception e) {
            logger.error("Error checking TOTP verification: {}", e.getMessage(), e);
            sendErrorResponse(response, "Authentication error");
            return false;
        }
    }

    private void sendTotpRequiredResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("message", "TOTP verification required for this operation");
        errorResponse.put("errorType", "TOTP_VERIFICATION_REQUIRED");
        errorResponse.put("requiresTotp", true);

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("message", message);

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}