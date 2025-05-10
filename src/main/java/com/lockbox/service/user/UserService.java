package com.lockbox.service.user;

import java.util.List;
import java.util.Optional;

import com.lockbox.dto.authentication.registration.UserRegistrationDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.User;

public interface UserService {

    List<User> findAllUsers();

    Optional<User> findById(String id);

    User findByUsername(String username);

    UserProfileResponseDTO fetchUserProfile(String userId) throws Exception;

    User createUser(UserRegistrationDTO userRegistrationDTO) throws Exception;

    void deleteUser(String id);
}
