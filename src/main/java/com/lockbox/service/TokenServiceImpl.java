package com.lockbox.service;

import com.lockbox.model.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class TokenServiceImpl implements TokenService {

    // Generate a secure key for signing tokens
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 900000L; // 15 minutes in milliseconds

    // Generate JWT token for a user
    @Override
    public String generateToken(User user) {
        return Jwts.builder().setSubject(user.getUsername()).claim("userId", user.getId()) // Include userId in the
                                                                                           // token
                .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY).compact();
    }

    // Validate the JWT token
    @Override
    public boolean validateToken(String token) {
        try {
            getClaims(token); // Parsing ensures token validity
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false; // Token invalid or expired
        }
    }

    // Extract username (subject) from the JWT token
    @Override
    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject();
    }

    // Extract userId from the JWT token
    @Override
    public String getUserIdFromToken(String token) {
        return getClaims(token).get("userId", String.class);
    }

    // Check if the token is expired
    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    // Extract claims from the JWT token
    private Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();
    }
}
