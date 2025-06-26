package com.lockbox.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/*
 * TODO: Might want to take into consideration the following:
 * 
 * 1. Implement monitoring to track:
 * 
 *  - How often legitimate users hit the rate limit
 *  - Distribution of attempts per session
 *  - If you see many users hitting limits, consider adjustin
 * 
 *  2. Consider progressive rate limiting where repeated patterns of hitting the limit result in longer windows (10 min, then 30 min, etc.)
 */
@Service
public class SecurityRateLimiterService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityRateLimiterService.class);

    private static final int MAX_REQUESTS_PER_WINDOW = 7;
    private static final int RESET_WINDOW_MINUTES = 5;
    private static final int MIN_DELAY_MS = 300;
    private static final int MAX_ADDITIONAL_DELAY_MS = 200;
    private final Random random = new SecureRandom();

    // Map to track requests by IP address
    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    private static class RequestCounter {
        private int count = 0;
        private Instant resetTime = Instant.now().plus(Duration.ofMinutes(RESET_WINDOW_MINUTES));

        public void increment() {
            count++;
        }

        public int getCount() {
            return count;
        }

        public boolean isExpired() {
            return Instant.now().isAfter(resetTime);
        }

        public void reset() {
            count = 0;
            resetTime = Instant.now().plus(Duration.ofMinutes(RESET_WINDOW_MINUTES));
        }
    }

    // Check if a request should be rate limited
    public boolean isRateLimited(String clientIP) {
        // Skip rate limiting if we can't identify the client
        if (clientIP == null || clientIP.isEmpty()) {
            logger.info("Skipping rate limiting - no client IP provided");
            return false;
        }

        RequestCounter counter = requestCounts.computeIfAbsent(clientIP, k -> new RequestCounter());

        if (counter.isExpired()) {
            counter.reset();
        }

        counter.increment();
        int currentCount = counter.getCount();

        // More extensive logging
        if (currentCount > MAX_REQUESTS_PER_WINDOW) {
            logger.info("Rate limit exceeded: {} requests for IP {} (limit: {})", currentCount, clientIP,
                    MAX_REQUESTS_PER_WINDOW);
            return true;
        } else {
            logger.info("Request {} of {} for IP {}", currentCount, MAX_REQUESTS_PER_WINDOW, clientIP);
            return false;
        }
    }

    // Keep the parameterless version for backward compatibility
    public boolean isRateLimited() {
        String clientIP = getClientIP();
        return isRateLimited(clientIP);
    }

    // Apply consistent timing with randomization to prevent timing attacks
    public void applyConsistentTiming() {
        try {
            // Base delay plus random component (300-500ms total)
            int delay = MIN_DELAY_MS + random.nextInt(MAX_ADDITIONAL_DELAY_MS + 1);
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String getClientIP() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();

            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    return xForwardedFor.split(",")[0].trim();
                }
                return request.getRemoteAddr();
            }
            // Fallback when outside a request context
            return "unknown-ip";
        } catch (Exception e) {
            logger.warn("Error getting client IP", e);
            return "error-getting-ip";
        }
    }

    @Scheduled(fixedRate = 60000) // Run every minute
    public void cleanupExpiredEntries() {
        requestCounts.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}