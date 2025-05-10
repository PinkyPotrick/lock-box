package com.lockbox.service.profile;

import com.lockbox.dto.userprofile.UserProfileDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;

public interface ProfileEncryptionService {

    /**
     * Encrypts the user profile data to be sent to the client.
     * 
     * @param profileData - The user profile data to be encrypted
     * @return A {@link UserProfileResponseDTO} containing the encrypted user profile data
     * @throws Exception
     */
    UserProfileResponseDTO encryptUserProfileResponseDTO(UserProfileDTO profileData) throws Exception;
}
