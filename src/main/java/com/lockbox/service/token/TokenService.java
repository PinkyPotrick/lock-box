package com.lockbox.service.token;

import java.util.Date;

import com.lockbox.model.User;

public interface TokenService {

    String generateToken(User user, String displayName);

    boolean validateToken(String token);

    Date getExpirationDateFromToken(String token);

    String getUsernameFromToken(String token);

    String getUserIdFromToken(String token);
}