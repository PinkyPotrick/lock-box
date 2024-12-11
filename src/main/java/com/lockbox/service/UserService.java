package com.lockbox.service;

import java.util.List;
import java.util.Optional;

import com.lockbox.dto.UserProfileResponseDTO;
import com.lockbox.dto.UserProfileUpdateRequestDTO;
import com.lockbox.dto.UserProfileUpdateResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.model.User;

public interface UserService {
    public List<User> findAllUsers();

    public Optional<User> findById(String id);

    public User findByUsername(String username);

    public UserProfileResponseDTO findUserProfileByUserId(String id);

    public User createUser(UserRegistrationDTO userRegistrationDTO) throws Exception;

    public UserProfileUpdateResponseDTO updateUserProfile(String id, UserProfileUpdateRequestDTO userDetails);

    public void deleteUser(String id);
}
