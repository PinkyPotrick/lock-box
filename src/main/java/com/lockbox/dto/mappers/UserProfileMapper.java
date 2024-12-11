package com.lockbox.dto.mappers;

import com.lockbox.dto.UserProfileDTO;
import com.lockbox.model.User;

public class UserProfileMapper {

    public UserProfileDTO toDto(final User user) {
        if (user == null) {
            return null;
        }

        UserProfileDTO userDTO = new UserProfileDTO();
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        userDTO.setCreatedAt(user.getCreatedAt());

        return userDTO;
    }

    public User fromDto(final UserProfileDTO userDTO) {
        if (userDTO == null) {
            return null;
        }

        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setCreatedAt(userDTO.getCreatedAt());

        return user;
    }
}
