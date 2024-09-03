package com.lockbox.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.EncryptedDataAesCbcDTO;
import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.DataTypesUtils;
import com.lockbox.utils.EncryptionUtils;

import jakarta.servlet.http.HttpSession;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@Service
public class SrpService {

    private static final SecureRandom random = new SecureRandom();
    // The group parameter N, a large prime number.
    private static final BigInteger N = new BigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187", 16);
    private static final BigInteger g = BigInteger.valueOf(2); // The group parameter g, a generator modulo N.

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HttpSession httpSession;

    /**
     * Initiates the SRP (Secure Remote Password) handshake process by generating the server's public value (B) and the
     * salt.
     * 
     * This method corresponds to the first step of the SRP protocol, where the server sends its public value (B) and a
     * unique salt to the client. The client uses these values, along with its own private value (A), to compute a
     * shared secret that will be used for further authentication steps.
     * 
     * @param srpParams - The SRP parameters received from the client, including the client's public value (A) and
     *                  username.
     * @return A {@link SrpParamsResponseDTO} containing the server's public value (B) and the salt, to be sent back to
     *         the client.
     * @throws Exception
     */
    public SrpParamsResponseDTO initiateSrpHandshake(SrpParamsDTO srpParams) throws Exception {
        // Decrypt the received data
        String derivedUsername = rsaKeyPairService.decryptWithServerPrivateKey(srpParams.getUsername());

        EncryptedDataAesCbcDTO encryptedClientPublicValueA = srpParams.getEncryptedClientPublicValueA();
        if (encryptedClientPublicValueA == null) {
            throw new RuntimeException("The public key cannot be empty");
        }
        BigInteger clientPublicValueA = new BigInteger(EncryptionUtils.decryptWithAESCBC(
                encryptedClientPublicValueA.getEncryptedDataBase64(), encryptedClientPublicValueA.getIvBase64(),
                encryptedClientPublicValueA.getHmacBase64(), srpParams.getHelperAesKey()), 16);

        EncryptedDataAesCbcDTO encryptedClientPublicKey = srpParams.getEncryptedClientPublicKey();
        if (encryptedClientPublicKey == null) {
            throw new RuntimeException("The public key cannot be empty");
        }
        String clientPublicKey = EncryptionUtils.decryptWithAESCBC(encryptedClientPublicKey.getEncryptedDataBase64(),
                encryptedClientPublicKey.getIvBase64(), encryptedClientPublicKey.getHmacBase64(),
                srpParams.getHelperAesKey());

        // Retrieve user information
        User user = userRepository.findByUsername(derivedUsername);
        if (user == null) {
            throw new RuntimeException("Invalid credentials");
        }
        BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

        // The salt needs to be decrypted first
        String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

        // Compute SRP variables
        BigInteger serverPrivateValueB = generateRandomPrivateValue();
        BigInteger serverPublicValueB = computeB(userVerifier, serverPrivateValueB);

        // Store temporary user values in session
        httpSession.setAttribute("clientPublicValueA", clientPublicValueA);
        httpSession.setAttribute("serverPublicValueB", serverPublicValueB);
        httpSession.setAttribute("serverPrivateValueB", serverPrivateValueB);
        httpSession.setAttribute("derivedUsername", derivedUsername);
        httpSession.setAttribute("clientPublicKey", clientPublicKey);

        // Create the response with the encrypted data
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        SrpParamsResponseDTO srpParamsResponse = new SrpParamsResponseDTO();
        EncryptedDataAesCbc encryptedServerPublicValueB = EncryptionUtils
                .encryptWithAESCBC(serverPublicValueB.toString(16), aesKey);
        srpParamsResponse.setEncryptedServerPublicValueB(encryptedDataAesCbcMapper.toDto(encryptedServerPublicValueB));
        srpParamsResponse.setHelperSrpParamsAesKey(encryptedServerPublicValueB.getAesKeyBase64());
        srpParamsResponse.setSalt(salt);

        return srpParamsResponse;
    }

    /**
     * Verifies the client's proof (M1) and completes the SRP (Secure Remote Password) authentication process.
     * 
     * This method handles the second phase of the SRP protocol, where the server verifies the client's proof of the
     * shared secret (M1). If the verification is successful, the server computes its own proof (M2) and generates a
     * session token for the authenticated client. These values are then returned to the client to complete the mutual
     * authentication process.
     * 
     * @param userLogin - The login data received from the client, typically including the client's public value (A),
     *                  proof (M1), and username.
     * @return A {@link UserLoginResponseDTO} containing the server's proof (M2) and the session token, to be sent back
     *         to the client.
     * @throws Exception
     */
    public UserLoginResponseDTO verifyClientProofAndAuthenticate(UserLoginDTO userLogin) throws Exception {
        // Decrypt the received data
        String encryptedClientProofM1 = userLogin.getEncryptedClientProofM1();
        String clientProofM = rsaKeyPairService.decryptWithServerPrivateKey(encryptedClientProofM1);

        // Retrieve session data and user information
        BigInteger clientPublicValueA = (BigInteger) httpSession.getAttribute("clientPublicValueA");
        BigInteger serverPublicValueB = (BigInteger) httpSession.getAttribute("serverPublicValueB");
        BigInteger serverPrivateValueB = (BigInteger) httpSession.getAttribute("serverPrivateValueB");
        String derivedUsername = (String) httpSession.getAttribute("derivedUsername");
        String clientPublicKey = (String) httpSession.getAttribute("clientPublicKey");

        // Abort if A % N == 0
        if (clientPublicValueA.mod(N).equals(BigInteger.ZERO)) {
            throw new RuntimeException("Authentication failed: Invalid client value A.");
        }

        // Retrieve user information
        User user = userRepository.findByUsername(derivedUsername);
        if (user == null || clientPublicValueA == null || serverPublicValueB == null || serverPrivateValueB == null) {
            throw new RuntimeException("Session expired or invalid");
        }
        BigInteger userVerifier = new BigInteger(user.getVerifier(), 16);

        // The salt needs to be decrypted first
        String salt = rsaKeyPairService.decryptWithServerPrivateKey(user.getSalt());

        // Compute SRP variables
        BigInteger scramblingParameterU = computeU(serverPublicValueB);
        BigInteger sharedSecretS = computeS(clientPublicValueA, userVerifier, scramblingParameterU,
                serverPrivateValueB);
        String sessionKeyK = computeK(sharedSecretS);
        String serverProofM1 = computeM1(derivedUsername, salt, clientPublicValueA, serverPublicValueB, sessionKeyK);

        // Compare the client's M1 with the server's M1, if the values are equal then
        // both the client and server share the same secret
        if (!serverProofM1.equals(clientProofM)) {
            throw new RuntimeException("Proof verification failed. Authorization aborted!");
        }

        String serverProofM2 = computeM2(clientPublicValueA, serverProofM1, sessionKeyK);
        String sessionToken = tokenService.generateToken(user);

        // Clear session attributes after successful authentication
        httpSession.invalidate();

        // Create the response with the encrypted data
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        UserLoginResponseDTO userLoginResponse = new UserLoginResponseDTO();
        EncryptedDataAesCbc encryptedClientPublicKey = EncryptionUtils.encryptWithAESCBC(user.getPublicKey(), aesKey);
        EncryptedDataAesCbc encryptedClientPrivateKey = EncryptionUtils.encryptWithAESCBC(user.getPrivateKey(), aesKey);
        EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken, aesKey);
        String encryptedServerProofM2 = rsaKeyPairService.encryptWithPublicKey(serverProofM2, clientPublicKey);
        userLoginResponse.setEncryptedUserPublicKey(encryptedDataAesCbcMapper.toDto(encryptedClientPublicKey));
        userLoginResponse.setEncryptedUserPrivateKey(encryptedDataAesCbcMapper.toDto(encryptedClientPrivateKey));
        userLoginResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
        userLoginResponse.setEncryptedServerProofM2(encryptedServerProofM2);
        userLoginResponse.setHelperAuthenticateAesKey(encryptedSessionToken.getAesKeyBase64());

        return userLoginResponse;
    }

    /**
     * Generates a random private value (b) using 32 bytes of randomness.
     *
     * @return A random BigInteger value.
     */
    private BigInteger generateRandomPrivateValue() {
        byte[] randomBytes = new byte[32]; // 32 bytes = 256 bits
        random.nextBytes(randomBytes);
        return new BigInteger(1, randomBytes); // Convert to BigInteger, treating bytes as positive
    }

    /**
     * Computes the server's public value B using the formula B = (v + g^b % N) % N.
     *
     * @param v - The verifier.
     * @param b - The server's private value.
     * @return The server's public value B.
     */
    private BigInteger computeB(BigInteger v, BigInteger b) {
        BigInteger gb = g.modPow(b, N); // Compute g^b % N
        return v.add(gb).mod(N); // Compute (v + g^b) % N
    }

    /**
     * Computes the scrambling parameter u in the SRP protocol.
     *
     * The parameter u is derived from the first 32 bits (4 bytes) of the SHA1 hash of B. It is converted into a
     * BigInteger as an unsigned integer.
     *
     * @param B - The server's public value (B) as a BigInteger.
     * @return The computed scrambling parameter u as a BigInteger.
     * @throws NoSuchAlgorithmException If SHA-1 algorithm is not available.
     */
    private BigInteger computeU(BigInteger B) throws NoSuchAlgorithmException {
        String B_hex = B.toString(16); // Convert B to a hex string

        // Compute the SHA-1 hash of B
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] B_hash = sha1.digest(DataTypesUtils.hexStringToByteArray(B_hex));

        byte[] first32Bits = new byte[4];
        System.arraycopy(B_hash, 0, first32Bits, 0, 4);

        // Convert the first 4 bytes to a BigInteger (unsigned 32-bit integer)
        return new BigInteger(1, first32Bits);
    }

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
    private BigInteger computeS(BigInteger A, BigInteger v, BigInteger u, BigInteger b) {
        BigInteger vu = v.modPow(u, N); // Compute v^u % N
        BigInteger Avu = A.multiply(vu).mod(N); // Compute A * v^u % N
        return Avu.modPow(b, N); // Compute (A * v^u)^b % N
    }

    /**
     * Computes the session key K using the SHA_Interleave function.
     *
     * SHA_Interleave is used in SRP-SHA1 to generate a session key that is twice as long as the 160-bit output of SHA1.
     * The process involves interleaving two SHA1 hashes derived from the even and odd bytes of the input.
     *
     * @param S The shared secret S as a BigInteger.
     * @return The session key K as a hexadecimal string.
     * @throws NoSuchAlgorithmException If SHA-1 algorithm is not available.
     */
    private String computeK(BigInteger S) throws NoSuchAlgorithmException {
        // Convert S to a byte array and remove leading zeros
        byte[] T = S.toByteArray();
        T = DataTypesUtils.removeLeadingZeros(T);

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
        return DataTypesUtils.bytesToHex(K_bytes);
    }

    /**
     * Computes the server's first proof M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K).
     * 
     * @param username - The user's name (U).
     * @param salt     - The salt value (s) used in SRP.
     * @param A        - The client's public value A.
     * @param B        - The server's public value B.
     * @param K        - The session key K derived from the shared secret.
     * @return The client's proof M as a hex string.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
     */
    private String computeM1(String username, String salt, BigInteger A, BigInteger B, String K)
            throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Convert BigInteger to byte arrays with leading zero if necessary
        byte[] aBytes = DataTypesUtils.toFixedLengthByteArray(A, 32); // 32 bytes <=> 256 bits
        byte[] bBytes = DataTypesUtils.toFixedLengthByteArray(B, 32); // 32 bytes <=> 256 bits
        byte[] N_bytes = DataTypesUtils.toFixedLengthByteArray(N, 32); // 32 bytes <=> 256 bits
        byte[] g_bytes = DataTypesUtils.toFixedLengthByteArray(g, 32); // 32 bytes <=> 256 bits

        // Hash N and g
        byte[] H_N = sha256.digest(N_bytes);
        byte[] H_g = sha256.digest(g_bytes);

        // XOR H_N and H_g
        byte[] H_N_XOR_H_g = new byte[H_N.length];
        for (int i = 0; i < H_N.length; i++) {
            H_N_XOR_H_g[i] = (byte) (H_N[i] ^ H_g[i]);
        }

        sha256.reset();
        sha256.update(H_N_XOR_H_g);
        sha256.update(username.getBytes(StandardCharsets.UTF_8));
        sha256.update(salt.getBytes(StandardCharsets.UTF_8));
        sha256.update(aBytes);
        sha256.update(bBytes);
        sha256.update(K.getBytes(StandardCharsets.UTF_8));

        byte[] digest = sha256.digest();
        StringBuilder hexString = new StringBuilder(2 * digest.length);
        for (byte b : digest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Computes the server's second proof M2 = H(A | M1 | K).
     * 
     * @param A  - The client's public value A.
     * @param M1 - The server's first proof M1.
     * @param K  - The session key K derived from the shared secret.
     * @return The final SHA-256 digest as a hex string.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
     */
    private String computeM2(BigInteger A, String M1, String K) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Convert BigInteger A to byte array with leading zero if necessary
        byte[] aBytes = DataTypesUtils.toFixedLengthByteArray(A, 32); // 32 bytes <=> 256 bits

        sha256.update(aBytes);
        sha256.update(M1.getBytes(StandardCharsets.UTF_8));
        sha256.update(K.getBytes(StandardCharsets.UTF_8));

        byte[] digest = sha256.digest();
        StringBuilder hexString = new StringBuilder(2 * digest.length);
        for (byte b : digest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
