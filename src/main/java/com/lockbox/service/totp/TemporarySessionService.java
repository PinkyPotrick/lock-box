package com.lockbox.service.totp;

public interface TemporarySessionService {

    String createTemporarySession(String userId);

    String validateTemporarySession(String sessionId);

    void removeTemporarySession(String sessionId);
}