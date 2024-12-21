package com.lockbox.service;

import com.lockbox.model.User;

public interface TokenService {

    String generateToken(User user);

    boolean validateToken(String token);

    String getUsernameFromToken(String token);

    String getUserIdFromToken(String token);
}