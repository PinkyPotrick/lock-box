package com.lockbox.dto.credential;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.Credential;

@Component
public class CredentialMapper {

    /**
     * Convert a Credential entity to a CredentialResponseDTO
     * 
     * @param credential The Credential entity
     * @return CredentialResponseDTO
     */
    public CredentialResponseDTO toResponseDTO(Credential credential) {
        if (credential == null) {
            return null;
        }

        CredentialResponseDTO dto = new CredentialResponseDTO();
        dto.setId(credential.getId());
        dto.setUserId(credential.getUserId());
        dto.setDomainId(credential.getDomainId());
        dto.setVaultId(credential.getVaultId());
        dto.setUsername(credential.getUsername());
        dto.setEmail(credential.getEmail());
        dto.setPassword(credential.getPassword());
        dto.setNotes(credential.getNotes());
        dto.setCategory(credential.getCategory());
        dto.setFavorite(Boolean.valueOf(credential.getFavorite()));
        dto.setCreatedAt(credential.getCreatedAt());
        dto.setUpdatedAt(credential.getUpdatedAt());
        dto.setLastUsed(credential.getLastUsed());

        return dto;
    }

    /**
     * Convert a list of Credential entities to a list of CredentialResponseDTOs
     * 
     * @param credentials The list of Credential entities
     * @return List of CredentialResponseDTOs
     */
    public List<CredentialResponseDTO> toResponseDTOList(List<Credential> credentials) {
        if (credentials == null) {
            return null;
        }

        return credentials.stream().map(this::toResponseDTO).collect(Collectors.toList());
    }

    /**
     * Convert a CredentialRequestDTO to a Credential entity
     * 
     * @param dto The CredentialRequestDTO
     * @return Credential entity
     */
    public Credential toEntity(CredentialRequestDTO dto) {
        if (dto == null) {
            return null;
        }

        Credential credential = new Credential();
        credential.setUserId(dto.getUserId());
        credential.setDomainId(dto.getDomainId());
        credential.setVaultId(dto.getVaultId());
        credential.setUsername(dto.getUsername());
        credential.setEmail(dto.getEmail());
        credential.setPassword(dto.getPassword());
        credential.setNotes(dto.getNotes());
        credential.setCategory(dto.getCategory());
        credential.setFavorite(dto.getFavorite() != null ? dto.getFavorite().toString() : Boolean.FALSE.toString());

        return credential;
    }

    /**
     * Update a Credential entity from a CredentialRequestDTO
     * 
     * @param entity The existing Credential entity
     * @param dto    The CredentialRequestDTO with updated data
     * @return Updated Credential entity
     */
    public Credential updateEntityFromDTO(Credential entity, CredentialRequestDTO dto) {
        if (entity == null || dto == null) {
            return entity;
        }

        if (dto.getUserId() != null) {
            entity.setUserId(dto.getUserId());
        }

        if (dto.getDomainId() != null) {
            entity.setDomainId(dto.getDomainId());
        }

        if (dto.getVaultId() != null) {
            entity.setVaultId(dto.getVaultId());
        }

        if (dto.getUsername() != null) {
            entity.setUsername(dto.getUsername());
        }

        if (dto.getEmail() != null) {
            entity.setEmail(dto.getEmail());
        }

        if (dto.getPassword() != null) {
            entity.setPassword(dto.getPassword());
        }

        if (dto.getNotes() != null) {
            entity.setNotes(dto.getNotes());
        }

        if (dto.getCategory() != null) {
            entity.setCategory(dto.getCategory());
        }

        if (dto.getFavorite() != null) {
            entity.setFavorite(dto.getFavorite().toString());
        }

        return entity;
    }
}