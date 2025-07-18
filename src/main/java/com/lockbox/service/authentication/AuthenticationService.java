package com.lockbox.service.authentication;

public interface AuthenticationService {
    void logout();

    void recordSuccessfulAuthentication(String userId) throws Exception;

    void recordFailedAuthentication(String userId, String reason);

    boolean isNewDeviceOrLocation(String userId, String ipAddress);

    int getRecentFailedAttempts(String userId);
}
