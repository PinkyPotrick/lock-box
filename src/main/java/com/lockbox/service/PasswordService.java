package com.lockbox.service;

import com.lockbox.repository.PasswordRepository;
import com.lockbox.model.Password;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PasswordService {

    @Autowired
    private PasswordRepository passwordRepository;

    public List<Password> getAllPasswords() {
        return passwordRepository.findAll();
    }

    public Password getPasswordById(String id) {
        return passwordRepository.getReferenceById(id);
    }

    public Password createPassword(Password password) {
        return passwordRepository.save(password);
    }

    public Password updatePassword(String id, Password newPassword) {
        Password password = passwordRepository.getReferenceById(id);
        
        password.setPassword(newPassword.getPassword());
        password.setUsername(newPassword.getUsername());
        password.setWebsite(newPassword.getWebsite());

        return passwordRepository.save(password);
    }

    public Password savePassword(Password password) {
        return passwordRepository.save(password);
    }

    public void deletePassword(String id) {
        passwordRepository.deleteById(id);
    }
}
