package com.lockbox.service;

import com.lockbox.dto.UserProfileResponseDTO;
import com.lockbox.dto.UserProfileUpdateRequestDTO;
import com.lockbox.dto.UserProfileUpdateResponseDTO;
import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.UserRegistrationMapper;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.validators.UserValidator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserValidator userValidator;

    @Autowired
    private UserServerEncryptionService userServerEncryptionService;

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public UserProfileResponseDTO findUserProfileByUserId(String id) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'findUserProfileByUserId'");
    }

    @Override
    public User createUser(UserRegistrationDTO userRegistrationDTO) throws Exception {
        userValidator.validate(userRegistrationDTO);
        UserRegistrationMapper userRegistrationMapper = new UserRegistrationMapper();
        User decryptedUser = userRegistrationMapper.fromDto(userRegistrationDTO);
        User encryptedUser = userServerEncryptionService.encryptServerData(decryptedUser);
        return userRepository.save(encryptedUser);
    }

    @Override
    public UserProfileUpdateResponseDTO updateUserProfile(String id, UserProfileUpdateRequestDTO userDetails) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'updateUserProfile'");
    }

    @Override
    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }
}
