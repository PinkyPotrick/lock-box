package com.lockbox.service;

import java.util.List;
import java.util.Optional;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.model.User;

public interface UserService {
    public List<User> findAllUsers();

    public Optional<User> findById(String id);

    public User findByUsername(String username);

    public User createUser(UserRegistrationDTO userRegistrationDTO) throws Exception;

    public User updateUser(String id, User userDetails);

    public void deleteUser(String id);
}
