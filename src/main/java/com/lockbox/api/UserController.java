package com.lockbox.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.User;
import com.lockbox.service.user.UserService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<List<User>> getAllUsers() {
        try {
            List<User> users = userService.findAllUsers();
            return new ResponseEntityBuilder<List<User>>().setData(users).setMessage("Users retrieved successfully")
                    .build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch users");
        }
    }

    @GetMapping("/profile")
    public ResponseEntityDTO<UserProfileResponseDTO> getUserProfile() {
        try {
            String userId = securityUtils.getCurrentUserId();
            UserProfileResponseDTO userProfileResponse = userService.fetchUserProfile(userId);
            return new ResponseEntityBuilder<UserProfileResponseDTO>().setData(userProfileResponse)
                    .setMessage("Profile retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Fetching profile failed");
        }
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntityDTO<Void> deleteUser(@PathVariable String id) {
        try {
            userService.deleteUser(id);
            return new ResponseEntityBuilder<Void>().setMessage("User deleted successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to delete user");
        }
    }
}