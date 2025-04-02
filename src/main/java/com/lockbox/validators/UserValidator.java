package com.lockbox.validators;

import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.EncryptionUtils;

@Component
public class UserValidator {

    @Autowired
    private UserRepository userRepository;

    public void validate(UserRegistrationDTO userRegistrationDTO) throws Exception {
        String derivedUsername = userRegistrationDTO.getDerivedUsername();
        String username = EncryptionUtils.decryptUsername(derivedUsername, userRegistrationDTO.getDerivedKey());
        validateUsername(username, derivedUsername);
        validateEmail(userRegistrationDTO.getEmail());
        validateSalt(userRegistrationDTO.getSalt());
        validateVerifier(userRegistrationDTO.getClientVerifier());
    }

    private void validateUsername(String username, String derivedUsername) throws Exception {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }

        if (!Pattern.matches("^[a-zA-Z0-9_]+$", username)) {
            throw new IllegalArgumentException("Invalid username format.");
        }

        if (userRepository.findByUsername(derivedUsername) != null) {
            throw new Exception("Username already exists"); // TODO THIS IS A SECURITY CONCERN !!!
        }
    }

    private void validateEmail(String email) throws Exception {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be empty.");
        }

        if (!Pattern.matches("^[A-Za-z0-9+_.-]+@(.+)$", email)) {
            throw new IllegalArgumentException("Invalid email format.");
        }

        if (userRepository.findByEmail(email) != null) {
            throw new Exception("This email is already used.");
        }
    }

    private void validateSalt(String salt) throws Exception {
        if (salt == null || salt.trim().isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be empty.");
        }
    }

    private void validateVerifier(String verifier) throws Exception {
        if (verifier == null || verifier.trim().isEmpty()) {
            throw new IllegalArgumentException("Verifier cannot be empty.");
        }
    }
}