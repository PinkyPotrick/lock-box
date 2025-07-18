package com.lockbox.service.security;

import java.util.Map;

public interface SecurityMonitoringService {

    boolean monitorFailedLoginAttempts(String userId, String ipAddress);

    boolean monitorNewDeviceLogin(String userId, String ipAddress, String userAgent);

    boolean monitorSuspiciousActivity(String userId, String ipAddress, String userAgent, Map<String, Object> metadata);

    boolean monitorCredentialChanges(String userId);
}
