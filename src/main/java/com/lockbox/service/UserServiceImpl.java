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
        // userValidator.validate(userRegistrationDTO);

        // UserRegistrationMapper userRegistrationMapper2 = new UserRegistrationMapper();
        // User user2 = userRegistrationMapper2.fromDto(userRegistrationDTO);
        // user2.setId(UUID.randomUUID().toString());
        // user2.setCreatedAt(rsaKeyPairService.encryptRSAWithPublicKey(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE), user2.getPublicKey()));
        // user2.setUsername(rsaKeyPairService.decryptRSAWithServerPrivateKey(userRegistrationDTO.getDerivedUsername())); // The username has 2 encryptions, only the first encryption is used in the database

        // TODO THE FOLLOWING ATTRIBUTES SHOULD ALSO BE ENCRYPTED IN THE DATABASE (NEED 3 ADDITIONAL TABLES) - at the end of all !!!
        // user.setVerifier(rsaKeyPairService.encryptWithPublicKey(user.getVerifier(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT
        // user.setPrivateKey(rsaKeyPairService.encryptWithPublicKey(user.getPrivateKey(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT
        // user.setPublicKey(rsaKeyPairService.encryptWithPublicKey(user.getPublicKey(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT

        // return userRepository.save(user2);

        // NEW CURRENT IMPLEMENTATION
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

    // public User updateUser(String id, User userDetails) {
    //     User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    //     user.setUsername(userDetails.getUsername());
    //     user.setEmail(userDetails.getEmail());
    //     user.setSalt(userDetails.getSalt());
    //     user.setVerifier(userDetails.getVerifier());
    //     return userRepository.save(user);
    // }

    @Override
    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }
}
