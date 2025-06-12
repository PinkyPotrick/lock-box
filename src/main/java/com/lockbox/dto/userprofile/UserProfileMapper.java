package com.lockbox.dto.userprofile;

import com.lockbox.model.User;

public class UserProfileMapper {

    public static UserProfileDTO toDto(final User user) {
        if (user == null) {
            return null;
        }

        UserProfileDTO userDTO = new UserProfileDTO();
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        userDTO.setCreatedAt(user.getCreatedAt());
        userDTO.setTotpEnabled(user.isTotpEnabled());

        return userDTO;
    }

    public static User fromDto(final UserProfileDTO userDTO) {
        if (userDTO == null) {
            return null;
        }

        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setCreatedAt(userDTO.getCreatedAt());
        user.setTotpEnabled(userDTO.isTotpEnabled());

        return user;
    }
}
