package com.lockbox.api;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.EncryptedDataAesCbcMapper;
import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.UserLoginDTO;
import com.lockbox.dto.UserLoginResponseDTO;
import com.lockbox.dto.SrpParamsDTO;
import com.lockbox.dto.SrpParamsResponseDTO;
import com.lockbox.dto.RegisterResponseDTO;
import com.lockbox.service.RSAKeyPairService;
import com.lockbox.service.SrpService;
import com.lockbox.service.TokenService;
import com.lockbox.service.UserService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.EncryptionUtils;
import com.lockbox.utils.ExceptionBuilder;

import jakarta.transaction.Transactional;

import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.model.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private SrpService srpService;

    @GetMapping("/public-key")
    public ResponseEntityDTO<String> getPublicKey() throws Exception {
        try {
            PublicKey publicKey = rsaKeyPairService.getPublicKey();

            ResponseEntityBuilder<String> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(rsaKeyPairService.getPublicKeyInPEM(publicKey)).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Error retrieving public key: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @Transactional
    @PostMapping("/register")
    public ResponseEntityDTO<RegisterResponseDTO> registerUser(@RequestBody UserRegistrationDTO userRegistration) {
        try {
            // Create the registered user and generate a session token
            User user = userService.createUser(userRegistration);
            String sessionToken = tokenService.generateToken(user);

            // Create the response with the encrypted session token of the client
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // AES-256
            SecretKey aesKey = keyGen.generateKey();
            EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
            RegisterResponseDTO registerResponse = new RegisterResponseDTO();
            EncryptedDataAesCbc encryptedSessionToken = EncryptionUtils.encryptWithAESCBC(sessionToken, aesKey);
            registerResponse.setEncryptedSessionToken(encryptedDataAesCbcMapper.toDto(encryptedSessionToken));
            registerResponse.setHelperAesKey(encryptedSessionToken.getAesKeyBase64());

            ResponseEntityBuilder<RegisterResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(registerResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Registering failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-params")
    public ResponseEntityDTO<SrpParamsResponseDTO> getSrpParams(@RequestBody SrpParamsDTO srpParams) {
        try {
            SrpParamsResponseDTO srpParamsResponse = srpService.initiateSrpHandshake(srpParams);
            ResponseEntityBuilder<SrpParamsResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(srpParamsResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Fetching SRP params failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping("/srp-authenticate")
    public ResponseEntityDTO<UserLoginResponseDTO> authenticateUser(@RequestBody UserLoginDTO userLogin) {
        try {
            UserLoginResponseDTO userLoginResponse = srpService.verifyClientProofAndAuthenticate(userLogin);
            ResponseEntityBuilder<UserLoginResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userLoginResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Authentication failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }
}
