package com.lockbox.api;

import com.lockbox.model.Password;
import com.lockbox.service.PasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/passwords")
public class PasswordController {

    @Autowired
    private PasswordService passwordService;

    @GetMapping
    public List<Password> getAllPasswords() {
        return passwordService.getAllPasswords();
    }

    @GetMapping("/{id}")
    public Password getPasswordById(@PathVariable String id) {
        return passwordService.getPasswordById(id);
    }

    @PostMapping
    public Password createPassword(@RequestBody Password password) {
        return passwordService.createPassword(password);
    }

    @PutMapping("/{id}")
    public Password updatePassword(@PathVariable String id, @RequestBody Password password) {
        return passwordService.updatePassword(id, password);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePassword(@PathVariable String id) {
        passwordService.deletePassword(id);
        return ResponseEntity.noContent().build();
    }
}
