package com.lockbox.service.authentication;

public interface AuthenticationService {
    void logout();

    void recordSuccessfulAuthentication(String userId) throws Exception;

    void recordFailedAuthentication(String userId, String reason) throws Exception;
}
