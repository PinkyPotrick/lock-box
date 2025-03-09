package com.lockbox.dto.mappers;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.model.User;

public class UserRegistrationMapper {

    public User fromDto(final UserRegistrationDTO userRegistrationDTO) throws Exception {
        if (userRegistrationDTO == null) {
            return null;
        }

        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setUsername(userRegistrationDTO.getDerivedUsername());
        user.setEmail(userRegistrationDTO.getEmail());
        user.setSalt(userRegistrationDTO.getSalt());
        user.setVerifier(userRegistrationDTO.getClientVerifier());
        user.setPublicKey(userRegistrationDTO.getClientPublicKey());
        user.setPrivateKey(userRegistrationDTO.getClientPrivateKey());
        user.setCreatedAt(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE));

        return user;
    }
}
