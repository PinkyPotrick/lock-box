package com.lockbox.api;

import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.authentication.login.UserLoginRequestDTO;
import com.lockbox.dto.authentication.login.UserLoginResponseDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationRequestDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationResponseDTO;
import com.lockbox.dto.authentication.srp.SrpParamsRequestDTO;
import com.lockbox.dto.authentication.srp.SrpParamsResponseDTO;
import com.lockbox.service.authentication.AuthenticationService;
import com.lockbox.service.authentication.SrpService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.ResponseEntityBuilder;

import jakarta.transaction.Transactional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    @Autowired
    private SrpService srpService;

    @Autowired
    private AuthenticationService authenticationService;

    @GetMapping("/public-key")
    public ResponseEntityDTO<String> getPublicKey() {
        try {
            PublicKey publicKey = rsaKeyPairService.getPublicKey();
            return new ResponseEntityBuilder<String>().setData(rsaKeyPairService.getPublicKeyInPEM(publicKey))
                    .setMessage("Public key retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Error retrieving public key");
        }
    }

    @Transactional
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntityDTO<UserRegistrationResponseDTO> registerUser(
            @RequestBody UserRegistrationRequestDTO userRegistration) {
        try {
            UserRegistrationResponseDTO registerResponse = srpService.registerUser(userRegistration);
            return new ResponseEntityBuilder<UserRegistrationResponseDTO>().setData(registerResponse)
                    .setMessage("Registration successful").setStatusCode(HttpStatus.CREATED.value()).build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Registration failed");
        }
    }

    @PostMapping("/srp-params")
    public ResponseEntityDTO<SrpParamsResponseDTO> getSrpParams(@RequestBody SrpParamsRequestDTO srpParams) {
        try {
            SrpParamsResponseDTO srpParamsResponse = srpService.initiateSrpHandshake(srpParams);
            return new ResponseEntityBuilder<SrpParamsResponseDTO>().setData(srpParamsResponse)
                    .setMessage("SRP parameters retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Authentication failed");
        }
    }

    // TEST USERS: pfilip 1234
    // usermare 12345678
    // Abelien abelien#PASS1234 (abelien@mail.com)

    @PostMapping("/srp-authenticate")
    public ResponseEntityDTO<UserLoginResponseDTO> authenticateUser(@RequestBody UserLoginRequestDTO userLogin) {
        try {
            UserLoginResponseDTO userLoginResponse = srpService.verifyClientProofAndAuthenticate(userLogin);
            return new ResponseEntityBuilder<UserLoginResponseDTO>().setData(userLoginResponse)
                    .setMessage("Authentication successful").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Authentication failed");
        }
    }

    @PostMapping("/logout")
    public ResponseEntityDTO<String> logout() {
        try {
            authenticationService.logout();
            return new ResponseEntityBuilder<String>().setData("Logged out successfully")
                    .setMessage("Logout successful").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Logout failed");
        }
    }
}