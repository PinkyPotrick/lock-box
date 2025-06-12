package com.lockbox.service.profile;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.dto.userprofile.UserProfileDTO;
import com.lockbox.dto.userprofile.UserProfileResponseDTO;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionServiceImpl;
import com.lockbox.utils.EncryptionUtils;

@Service
public class ProfileEncryptionServiceImpl implements ProfileEncryptionService {

    @Autowired
    private GenericEncryptionServiceImpl genericEncryptionService;

    /**
     * Encrypts the user profile data to be sent to the client.
     * 
     * @param profileData - The user profile data to be encrypted
     * @return A {@link UserProfileResponseDTO} containing the encrypted user profile data
     * @throws Exception
     */
    @Override
    public UserProfileResponseDTO encryptUserProfileResponseDTO(UserProfileDTO profileData) throws Exception {
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        UserProfileResponseDTO encryptedUserProfileDTO = new UserProfileResponseDTO();

        EncryptedDataAesCbc encryptedUserProfile = genericEncryptionService.encryptDTOWithAESCBC(profileData,
                EncryptedDataAesCbc.class, aesKey);

        encryptedUserProfileDTO.setEncryptedUserProfile(encryptedDataAesCbcMapper.toDto(encryptedUserProfile));
        encryptedUserProfileDTO.setHelperAesKey(encryptedUserProfile.getAesKeyBase64());
        encryptedUserProfileDTO.setTotpEnabled(profileData.isTotpEnabled());

        return encryptedUserProfileDTO;
    }
}