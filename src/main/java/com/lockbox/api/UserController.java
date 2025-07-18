package com.lockbox.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeCompleteResponseDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitRequestDTO;
import com.lockbox.dto.authentication.password.PasswordChangeInitResponseDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.User;
import com.lockbox.security.annotation.RequireTotpVerification;
import com.lockbox.service.authentication.SrpService;
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

    @Autowired
    private SrpService srpService;

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

    @PostMapping("/password-change/init")
    @RequireTotpVerification(operation = "CHANGE_PASSWORD")
    public ResponseEntityDTO<PasswordChangeInitResponseDTO> initiatePasswordChange(
            @RequestBody PasswordChangeInitRequestDTO passwordChangeInit) {
        try {
            PasswordChangeInitResponseDTO response = srpService.initiatePasswordChange(passwordChangeInit);
            return new ResponseEntityBuilder<PasswordChangeInitResponseDTO>().setData(response)
                    .setMessage("Password change process initiated").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to initiate password change");
        }
    }

    @PostMapping("/password-change/complete")
    @RequireTotpVerification(operation = "CHANGE_PASSWORD")
    public ResponseEntityDTO<PasswordChangeCompleteResponseDTO> completePasswordChange(
            @RequestBody PasswordChangeCompleteRequestDTO passwordChangeComplete) {
        try {
            PasswordChangeCompleteResponseDTO response = srpService.completePasswordChange(passwordChangeComplete);
            return new ResponseEntityBuilder<PasswordChangeCompleteResponseDTO>().setData(response)
                    .setMessage("Password changed successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to change password");
        }
    }
}