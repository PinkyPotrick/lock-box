package com.lockbox.service;

import com.lockbox.dto.UserRegistrationDTO;
import com.lockbox.dto.mappers.UserRegistrationMapper;
import com.lockbox.model.User;
import com.lockbox.repository.UserRepository;
import com.lockbox.validators.UserValidator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserValidator userValidator;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public Optional<User> findById(String id) {
        return userRepository.findById(id);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User createUser(UserRegistrationDTO userRegistrationDTO) throws Exception {
        userValidator.validate(userRegistrationDTO);

        UserRegistrationMapper userRegistrationMapper = new UserRegistrationMapper();
        User user = userRegistrationMapper.fromDto(userRegistrationDTO);
        user.setId(UUID.randomUUID().toString());
        user.setCreatedAt(rsaKeyPairService.encryptWithPublicKey(LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE), user.getPublicKey()));
        user.setUsername(rsaKeyPairService.decryptWithServerPrivateKey(userRegistrationDTO.getUsername())); // The username has 2 encryptions, only the first encryption is used in the database

        // TODO THE FOLLOWING ATTRIBUTES SHOULD ALSO BE ENCRYPTED IN THE DATABASE (NEED 3 ADDITIONAL TABLES)
        // user.setVerifier(rsaKeyPairService.encryptWithPublicKey(user.getVerifier(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT
        // user.setPrivateKey(rsaKeyPairService.encryptWithPublicKey(user.getPrivateKey(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT
        // user.setPublicKey(rsaKeyPairService.encryptWithPublicKey(user.getPublicKey(), user.getPublicKey())); // TODO REMEMBER THAT YOU ARE ENCRYPTING AND DECRYPTING THIS DATA AT SOME POINT

        return userRepository.save(user);
    }

    public User updateUser(String id, User userDetails) {
        User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        user.setUsername(userDetails.getUsername());
        user.setEmail(userDetails.getEmail());
        user.setSalt(userDetails.getSalt());
        user.setVerifier(userDetails.getVerifier());
        return userRepository.save(user);
    }

    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }
}
