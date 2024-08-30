package com.lockbox.service;

import com.lockbox.model.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class TokenService {

    // Generate a secure key for signing tokens
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 900000L; // 15 minutes in milliseconds

    // Generate JWT token for a user
    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY) // Automatically selects the algorithm based on the key
                .compact();
    }

    // Validate the JWT token
    public boolean validateToken(String token, User user) {
        try {
            String username = getClaims(token).getSubject();
            return (username.equals(user.getUsername()) && !isTokenExpired(token));
        } catch (JwtException | IllegalArgumentException e) {
            // Token is either invalid or expired
            return false;
        }
    }

    // Check if the token is expired
    private boolean isTokenExpired(String token) {
        Date expiration = getClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    // Extract claims from the JWT token
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY) // Use SecretKey instead of string
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
