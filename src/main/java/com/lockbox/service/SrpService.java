package com.lockbox.service;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
public class SrpService {

    private static final SecureRandom random = new SecureRandom();
    private static final BigInteger N = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187", 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k = BigInteger.valueOf(3); // Multiplier parameter

    // Step 1: Generate salt for the user during registration
    public String generateSalt() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return toHex(salt);
    }

    // Step 2: Compute the verifier (v) for the user during registration
    public String computeVerifier(String salt, String username, String password) {
        BigInteger x = computeX(salt, username, password);
        return g.modPow(x, N).toString(16);
    }

    // Compute the private value `x`
    private BigInteger computeX(String salt, String username, String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((salt + username + password).getBytes());
            return new BigInteger(1, digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Step 3: Generate server's private value `b`
    public BigInteger generatePrivateValue() {
        // return new BigInteger(256, random); // Generate a random 256-bit number
        return new BigInteger(512, random); // Increase from 256 bits to 512 bits
    }

    // Step 4: Compute server's public value `B`
    public BigInteger computeB(String verifier, BigInteger b) throws NoSuchAlgorithmException {
        // BigInteger v = new BigInteger(verifier, 16);

        // MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // digest.update(N.toByteArray());
        // digest.update(g.toByteArray());
        // BigInteger k = new BigInteger(1, digest.digest());

        // BigInteger thatFirstMultiply = k.multiply(v);
        // BigInteger thatModPow = g.modPow(b, N);
        // BigInteger partBeforeModN = k.multiply(v).add(g.modPow(b, N));
        // BigInteger withMod = (k.multiply(v).add(g.modPow(b, N))).mod(N);
        // BigInteger newApproach = (k.multiply(v).mod(N).add(g.modPow(b, N))).mod(N);
        // return (k.multiply(v).mod(N).add(g.modPow(b, N))).mod(N);

        BigInteger v = new BigInteger(verifier, 16);
        
        // Check sizes and values to ensure correctness
        BigInteger gPowB = g.modPow(b, N);
        
        // Ensure gPowB is significantly large to avoid negative bases
        if (gPowB.compareTo(v) <= 0) {
            System.out.println("Warning: g^b is not larger than v. Adjusting strategy.");
        }
        
        BigInteger B = (k.multiply(v).add(gPowB)).mod(N);
        
        // Adding a small offset or adjusting the scaling can help avoid negative base issues
        if (B.compareTo(k.multiply(v)) <= 0) {
            // Adding offset to ensure positive base; Not standard SRP, but necessary adjustment
            B = B.add(N);
        }
        
        return B;
    }

    // Step 5: Compute the scrambling parameter `u`
    public BigInteger computeU(BigInteger A, BigInteger B) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(A.toByteArray());
            digest.update(B.toByteArray());
            return new BigInteger(1, digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Step 6: Compute the shared secret `S`
    public BigInteger computeS(BigInteger A, BigInteger v, BigInteger u, BigInteger b) {
        return A.multiply(v.modPow(u, N)).modPow(b, N);
    }

    // Step 7: Compute the session key `K`
    public byte[] computeK(BigInteger S) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(S.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Step 8: Compute the client evidence message `M1`
    public String computeM1(BigInteger A, BigInteger B, BigInteger S, byte[] K) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(K);
            digest.update(A.toByteArray());
            digest.update(B.toByteArray());
            digest.update(S.toByteArray());
            return new BigInteger(1, digest.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Step 9: Compute the server evidence message `M2`
    public String computeM2(BigInteger A, String M1, BigInteger S, byte[] K) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(K);
            digest.update(A.toByteArray());
            digest.update(new BigInteger(M1, 16).toByteArray());
            digest.update(S.toByteArray());
            return new BigInteger(1, digest.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Utility method to convert byte array to hex string
    private String toHex(byte[] array) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : array) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
