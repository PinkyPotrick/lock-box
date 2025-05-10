package com.lockbox.api;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.User;
import com.lockbox.service.user.UserService;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public List<User> getAllUsers() {
        return userService.findAllUsers();
    }

    @GetMapping("/profile")
    public ResponseEntityDTO<UserProfileResponseDTO> getUserProfile() {
        try {
            String userId = securityUtils.getCurrentUserId();
            UserProfileResponseDTO userProfileResponse = userService.fetchUserProfile(userId);
            ResponseEntityBuilder<UserProfileResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(userProfileResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Fetching profile failed").throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}