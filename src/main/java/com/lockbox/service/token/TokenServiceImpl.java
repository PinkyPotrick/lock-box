package com.lockbox.service.token;

import com.lockbox.model.User;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenServiceImpl implements TokenService {

    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 900000L; // 15 minutes in milliseconds

    @Override
    public String generateToken(User user, String displayName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("displayName", displayName);

        String userId = user.getId(); // Get the ID
        System.out.println("User ID from user object: " + userId); // Debug print

        return Jwts.builder() //
                .setClaims(claims) //
                .setSubject(user.getUsername()) //
                .setIssuedAt(new Date()) //
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) //
                .signWith(SECRET_KEY) //
                .compact(); //
    }

    @Override
    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public Date getExpirationDateFromToken(String token) {
        return getClaims(token).getExpiration();
    }

    @Override
    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject();
    }

    @Override
    public String getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("userId", String.class);
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();
    }
}