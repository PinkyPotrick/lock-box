package com.lockbox.service.user;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.api.UserController;
import com.lockbox.dto.authentication.registration.UserRegistrationDTO;
import com.lockbox.dto.authentication.registration.UserRegistrationMapper;
import com.lockbox.dto.userprofile.UserProfileMapper;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.service.profile.ProfileEncryptionService;
import com.lockbox.validators.UserValidator;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserValidator userValidator;

    @Autowired
    private UserServerEncryptionServiceImpl userServerEncryptionService;

    @Autowired
    private ProfileEncryptionService profileEncryptionService;

    private final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public UserProfileResponseDTO fetchUserProfile(String userId) throws Exception {
        logger.info("Fetching profile for user ID: {}", userId);

        // Fetch user from repository by ID
        Optional<User> encryptedUserOpt = userRepository.findById(userId);
        if (!encryptedUserOpt.isPresent()) {
            logger.error("User not found with ID: {}", userId);
            throw new RuntimeException("User not found with ID: " + userId);
        }

        // Decrypt user data
        User encryptedUser = encryptedUserOpt.get();
        User decryptedUser = userServerEncryptionService.decryptServerData(encryptedUser);

        // Use the existing mapper to convert to DTO
        return profileEncryptionService.encryptUserProfileResponseDTO(UserProfileMapper.toDto(decryptedUser));
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
    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }
}
