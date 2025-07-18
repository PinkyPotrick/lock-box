package com.lockbox.service.profile;

import com.lockbox.dto.userprofile.UserProfileDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;

public interface ProfileEncryptionService {

    UserProfileResponseDTO encryptUserProfileResponseDTO(UserProfileDTO profileData) throws Exception;
}
