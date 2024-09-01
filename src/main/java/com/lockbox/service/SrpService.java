package com.lockbox.service;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class SrpService {

    private static final SecureRandom random = new SecureRandom();
    // private static final BigInteger N = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187", 16);  // The group parameter N, a large prime number.
    // private static final BigInteger g = BigInteger.valueOf(2); // The group parameter g, a generator modulo N.
    // private static final BigInteger k = BigInteger.valueOf(3); // Multiplier parameter

    public static final BigInteger N = new BigInteger("1362643368171802605024730761771234071407005688199");
    public static final BigInteger g = BigInteger.valueOf(2);
    public static final BigInteger k = BigInteger.valueOf(3);

    public BigInteger getN() {
        return N;
    }

    /**
     * Converts a hex string to a byte array.
     *
     * @param hexString - The hex string to convert.
     * @return The byte array representation of the hex string.
     */
    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                  + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Removes leading zeros from a byte array.
     *
     * @param bytes The byte array.
     * @return A new byte array with leading zeros removed.
     */
    private static byte[] removeLeadingZeros(byte[] bytes) {
        int start = 0;
        while (start < bytes.length && bytes[start] == 0) {
            start++;
        }
        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    /**
     * Converts a byte array to a hex string.
     *
     * @param bytes The byte array.
     * @return The hex string representation of the byte array.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Generates a random private value (b) using 32 bytes of randomness.
     *
     * @return A random BigInteger value.
     */
    public BigInteger generateRandomPrivateValue() {
        byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
        random.nextBytes(randomBytes);
        return new BigInteger(1, randomBytes); // Convert to BigInteger, treating bytes as positive
    }

    /**
     * Computes the server's public value B using the formula B = (k * v + g^b % N) % N.
     *
     * @param v - The verifier.
     * @param b - The server's private value.
     * @return The server's public value B.
     */
    public BigInteger computeB(BigInteger v, BigInteger b) {
        BigInteger gb = g.modPow(b, N); // Compute g^b % N
        BigInteger kv = k.multiply(v); // Compute k * v
        return kv.add(gb).mod(N); // Compute (k * v + g^b) % N
    }

    /**
     * Computes the server's proof H(A | M | K).
     * 
     * @param A - The client's public value A.
     * @param M - The client's proof M.
     * @param K - The session key K derived from the shared secret.
     * @return  The server's proof as a hexadecimal string.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
     */
    public String computeM(BigInteger A, String M, byte[] K) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Compute H(A | M | K)
        digest.update(A.toByteArray());
        digest.update(new BigInteger(M, 16).toByteArray());
        digest.update(K);

        return new BigInteger(1, digest.digest()).toString(16);
    }

    /**
     * Computes the scrambling parameter u in the SRP protocol.
     *
     * The parameter u is derived from the first 32 bits (4 bytes) of the SHA1 hash of B.
     * It is converted into a BigInteger as an unsigned integer.
     *
     * @param B - The server's public value (B) as a BigInteger.
     * @return The computed scrambling parameter u as a BigInteger.
     * @throws NoSuchAlgorithmException If SHA-1 algorithm is not available.
     */
    public BigInteger computeU(BigInteger B) throws NoSuchAlgorithmException {
        String B_hex = B.toString(16); // Convert B to a hex string

        // Compute the SHA-1 hash of B
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] B_hash = sha1.digest(hexStringToByteArray(B_hex));

        byte[] first32Bits = new byte[4];
        System.arraycopy(B_hash, 0, first32Bits, 0, 4);

        // Convert the first 4 bytes to a BigInteger (unsigned 32-bit integer)
        return new BigInteger(1, first32Bits); 
    }

    /**
     * serverPrivateValueB (B):32228892571253549088287946698901798891413593136237036128449505629902599122101
        B_hex = e3c41180be5b60438a833b944ac17d64034f8309
        [-29, -60, 17, -128, -66, 91, 96, 67, -118, -125, 59, -108, 74, -63, 125, 100, 3, 79, -125, 9,]
        B_hash = [B@2c0d85cf
        first32Bits = [B@74cd2519
        BigInteger of first32Bits = 1555257998

        scramblingParameterU:1555257998
        scramblingParameterU (mock expected):1699887217

        Convert B to Hexadecimal
        "e3c41180be5b60438a833b944ac17d64034f8309"

        SHA-1 Hash of B_hex
        [101, 77, 143, 113, 43, 108, -110, -8, -27, -64, -26, -14, -29, 72, 50, -8, -75, -9, -80, -19]
     */

    /**
     * Computes the shared session key S in the SRP protocol.
     *
     * S = (A * v^u) ^ b % N
     *
     * @param A - The client's public value (A) as a BigInteger.
     * @param v - The verifier (v) as a BigInteger.
     * @param u - The scrambling parameter (u) as a BigInteger.
     * @param b - The server's private value (b) as a BigInteger.
     * @return The computed shared session key S as a BigInteger.
     */
    public BigInteger computeS(BigInteger A, BigInteger v, BigInteger u, BigInteger b) {
        BigInteger vu = v.modPow(u, N); // Compute v^u % N
        BigInteger Avu = A.multiply(vu).mod(N); // Compute A * v^u % N
        return Avu.modPow(b, N); // Compute (A * v^u)^b % N
    }

    /**
     * Computes the session key K using the SHA_Interleave function.
     *
     * SHA_Interleave is used in SRP-SHA1 to generate a session key that is twice
     * as long as the 160-bit output of SHA1. The process involves interleaving
     * two SHA1 hashes derived from the even and odd bytes of the input.
     *
     * @param S The shared secret S as a BigInteger.
     * @return The session key K as a hexadecimal string.
     * @throws NoSuchAlgorithmException If SHA-1 algorithm is not available.
     */
    public String computeK(BigInteger S) throws NoSuchAlgorithmException {
        // Convert S to a byte array and remove leading zeros
        byte[] T = S.toByteArray();
        T = removeLeadingZeros(T);

        // If the length of T is odd, remove the first byte
        if (T.length % 2 != 0) {
            T = Arrays.copyOfRange(T, 1, T.length);
        }

        // Split T into even-numbered and odd-numbered bytes
        byte[] E = new byte[T.length / 2];
        byte[] F = new byte[T.length / 2];

        for (int i = 0; i < T.length / 2; i++) {
            E[i] = T[2 * i]; // Even-indexed bytes
            F[i] = T[2 * i + 1]; // Odd-indexed bytes
        }

        // Compute the SHA1 hashes of E and F
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] G = sha1.digest(E);
        byte[] H = sha1.digest(F);

        // Interleave the two hashes to form the session key K
        byte[] K_bytes = new byte[G.length + H.length];
        for (int i = 0; i < G.length; i++) {
            K_bytes[2 * i] = G[i];
            K_bytes[2 * i + 1] = H[i];
        }

        // Convert the interleaved byte array to a hex string
        return bytesToHex(K_bytes);
    }

    /**
     * Computes the server's proof M = H(H(N) XOR H(g) | H(U) | s | A | B | K).
     * 
     * @param username - The user's name (U).
     * @param salt - The salt value (s) used in SRP.
     * @param A - The client's public value A.
     * @param B - The server's public value B.
     * @param K - The session key K derived from the shared secret.
     * @return The client's proof M as a hexadecimal string.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
     */
    public String computeM1(String username, String salt, BigInteger A, BigInteger B, String K) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Compute H(N), H(g) and H(U)
        digest.update(N.toByteArray());
        byte[] H_N = digest.digest();

        digest.update(g.toByteArray());
        byte[] H_g = digest.digest();

        digest.update(username.getBytes());
        byte[] H_U = digest.digest();

        // XOR the hashes byte by byte H(N) XOR H(g)
        byte[] H_N_XOR_H_g = new byte[H_N.length];
        for (int i = 0; i < H_N.length; i++) {
            H_N_XOR_H_g[i] = (byte) (H_N[i] ^ H_g[i]);
        }

        // Convert K from a hex string to a byte array
        byte[] K_bytes = new BigInteger(K, 16).toByteArray();

        // Compute M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)
        digest.update(H_N_XOR_H_g);
        digest.update(H_U);
        digest.update(salt.getBytes());
        digest.update(A.toByteArray());
        digest.update(B.toByteArray());
        digest.update(K_bytes);

        return new BigInteger(1, digest.digest()).toString(16);
    }

    /**
     * Computes the server's proof H(A | M | K).
     * 
     * @param A The client's public value A.
     * @param M The client's proof M.
     * @param K The session key K derived from the shared secret.
     * @return  The server's proof as a hexadecimal string.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
     */
    public String computeM2(BigInteger A, String M, String K) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Convert K from a hexadecimal string to a byte array
        byte[] K_bytes = new BigInteger(K, 16).toByteArray();

        // Compute H(A | M | K)
        digest.update(A.toByteArray());
        digest.update(new BigInteger(M, 16).toByteArray());
        digest.update(K_bytes);

        return new BigInteger(1, digest.digest()).toString(16);
    }

    ///////// ---------------------------------- ABOVE ONLY CLEAN -------------------------------------

    public BigInteger computeX(String salt, String username, String password) throws NoSuchAlgorithmException {
        // Create a SHA-1 message digest instance
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // Step 1: Compute inner hash = SHA1(I | ":" | P)
        String userPassConcat = username + ":" + password;
        byte[] innerHash = sha1.digest(userPassConcat.getBytes(StandardCharsets.UTF_8));

        // Convert innerHash to a hexadecimal string
        String innerHashHex = bytesToHex(innerHash);

        // Step 2: Compute x = SHA1(s | innerHash)
        sha1.reset();
        sha1.update(hexStringToByteArray(salt));  // Convert salt from hex to bytes and update digest
        sha1.update(hexStringToByteArray(innerHashHex));  // Convert innerHashHex from hex to bytes and update digest
        byte[] xHash = sha1.digest();

        // Convert xHash (the result) to a BigInteger
        return new BigInteger(1, xHash);
    }

    public BigInteger computeS_FE(BigInteger B, BigInteger x, BigInteger a, BigInteger u) {
        System.out.println("[computeS] B:" + B);
        // Compute g^x % N
        BigInteger gx = g.modPow(x, N);
        System.out.println("[computeS] gx:" + gx);

        // Compute B - g^x
        BigInteger B_minus_gx = B.subtract(gx);
        System.out.println("[computeS] B_minus_gx:" + B_minus_gx);

        // Ensure B_minus_gx is non-negative by adding N if necessary
        // if (B_minus_gx.compareTo(BigInteger.ZERO) < 0) {
        //     System.out.println("[computeS] B_minus_gx < 0: We have to add N");
        //     B_minus_gx = B_minus_gx.add(N);
        //     System.out.println("[computeS] B_minus_gx += N:" + B_minus_gx);
        // }

        // Compute (B - g^x) % N
        B_minus_gx = B_minus_gx.mod(N);
        System.out.println("[computeS] B_minus_gx = B_minus_gx % N:" + B_minus_gx);
        System.out.println("[computeS] B_minus_gx % N:" + B_minus_gx);

        // Compute the exponent (a + u * x)
        BigInteger exp = a.add(u.multiply(x));
        System.out.println("[computeS] u * x:" + u.multiply(x));
        System.out.println("[computeS] a + u * x:" + exp);

        // Compute S = (B - g^x) ^ (a + u * x) % N
        BigInteger S = B_minus_gx.modPow(exp, N);
        System.out.println("[computeS] modExp(B_minus_gx, exp, N):" + S);

        return S;
    }
}
