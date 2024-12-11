package com.lockbox.api;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.UserProfileResponseDTO;
import com.lockbox.dto.UserProfileUpdateRequestDTO;
import com.lockbox.dto.UserProfileUpdateResponseDTO;
import com.lockbox.model.User;
import com.lockbox.service.TokenService;
import com.lockbox.service.UserServiceImpl;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserServiceImpl userService;

    @Autowired
    private TokenService tokenService;

    @GetMapping
    public List<User> getAllUsers() {
        return userService.findAllUsers();
    }

    // @GetMapping("/{id}")
    // public ResponseEntity<User> getUserById(@PathVariable String id) {
    // return userService.findById(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    // }

    // @GetMapping("/{id}/profile")
    // public ResponseEntity<User> getUserProfileById(@PathVariable String id) {
    // return userService.findById(id)
    // .map(ResponseEntity::ok)
    // .orElse(ResponseEntity.notFound().build());
    // }

    // public ResponseEntityDTO<UserLoginResponseDTO> authenticateUser(@RequestBody UserLoginDTO userLogin) {
    // try {
    // UserLoginResponseDTO userLoginResponse = srpService.verifyClientProofAndAuthenticate(userLogin);
    // ResponseEntityBuilder<UserLoginResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
    // return responseEntityBuilder.setData(userLoginResponse).build();
    // } catch (Exception e) {
    // ExceptionBuilder.create().setMessage("Authentication failed: " + e.getMessage())
    // .throwInternalServerErrorException();
    // return null;
    // }
    // }

    @GetMapping("/profile")
    public ResponseEntityDTO<UserProfileResponseDTO> getUserProfile(@RequestHeader("Authorization") String token) {
        try {
            String userId = tokenService.getUserIdFromToken(token.replace("Bearer ", ""));
            UserProfileResponseDTO userProfileResponse = userService.findUserProfileByUserId(userId);
            ResponseEntityBuilder<UserProfileResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userProfileResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Fetching profile failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/update")
    public ResponseEntityDTO<UserProfileUpdateResponseDTO> updateUser(@RequestBody UserProfileUpdateRequestDTO userDetails,
            @RequestHeader("Authorization") String token) {
        try {
            String userId = tokenService.getUserIdFromToken(token.replace("Bearer ", ""));
            UserProfileUpdateResponseDTO userProfileResponse = userService.updateUserProfile(userId, userDetails);
            ResponseEntityBuilder<UserProfileUpdateResponseDTO> responseEntityBuilder = new ResponseEntityBuilder<>();
            return responseEntityBuilder.setData(userProfileResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Fetching profile failed: " + e.getMessage())
                    .throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}