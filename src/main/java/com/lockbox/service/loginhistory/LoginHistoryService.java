package com.lockbox.service.loginhistory;

import java.time.LocalDateTime;

public interface LoginHistoryService {

    void recordSuccessfulLogin(String userId, String ipAddress, String userAgent) throws Exception;

    void recordFailedLogin(String userId, String ipAddress, String userAgent, String failureReason) throws Exception;

    double getLoginSuccessRate(String userId) throws Exception;

    int clearOldLoginHistory(String userId, LocalDateTime before) throws Exception;

    boolean isNewDeviceOrLocation(String userId, String ipAddress, String userAgent);

    int countRecentFailedAttempts(String userId);
}