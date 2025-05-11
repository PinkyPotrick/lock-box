package com.lockbox.dto.credential;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import com.lockbox.model.Credential;

/**
 * Component for mapping between Credential entities and DTOs.
 */
@Component
public class CredentialMapper {

    /**
     * Convert a Credential entity to a DTO.
     * 
     * @param credential The credential entity
     * @return The credential DTO
     */
    public CredentialDTO toDTO(Credential credential) {
        if (credential == null) {
            return null;
        }

        CredentialDTO dto = new CredentialDTO();
        dto.setId(credential.getId());
        dto.setUserId(credential.getUserId());
        dto.setVaultId(credential.getVaultId());
        dto.setDomainId(credential.getDomainId());
        dto.setUsername(credential.getUsername());
        dto.setEmail(credential.getEmail());
        dto.setPassword(credential.getPassword());
        dto.setNotes(credential.getNotes());
        dto.setCategory(credential.getCategory());
        dto.setFavorite(String.valueOf(Boolean.TRUE).equals(credential.getFavorite()));
        dto.setCreatedAt(credential.getCreatedAt());
        dto.setUpdatedAt(credential.getUpdatedAt());
        dto.setLastUsed(credential.getLastUsed());

        return dto;
    }

    /**
     * Convert a list of Credential entities to DTOs.
     * 
     * @param credentials The list of credential entities
     * @return The list of credential DTOs
     */
    public List<CredentialDTO> toDTOList(List<Credential> credentials) {
        if (credentials == null) {
            return null;
        }

        List<CredentialDTO> dtoList = new ArrayList<>();
        for (Credential credential : credentials) {
            dtoList.add(toDTO(credential));
        }

        return dtoList;
    }

    /**
     * Convert a CredentialDTO to a Credential entity.
     * 
     * @param dto The credential DTO
     * @return The credential entity
     */
    public Credential toEntity(CredentialDTO dto) {
        if (dto == null) {
            return null;
        }

        Credential credential = new Credential();
        if (dto.getId() != null) {
            credential.setId(dto.getId());
        }
        credential.setUserId(dto.getUserId());
        credential.setVaultId(dto.getVaultId());
        credential.setDomainId(dto.getDomainId());
        credential.setUsername(dto.getUsername());
        credential.setEmail(dto.getEmail());
        credential.setPassword(dto.getPassword());
        credential.setNotes(dto.getNotes());
        credential.setCategory(dto.getCategory());
        credential.setFavorite(dto.isFavorite() ? String.valueOf(Boolean.TRUE) : String.valueOf(Boolean.FALSE));
        credential.setCreatedAt(dto.getCreatedAt());
        credential.setUpdatedAt(dto.getUpdatedAt());
        credential.setLastUsed(dto.getLastUsed());

        return credential;
    }

    /**
     * Update a Credential entity from a DTO.
     * 
     * @param entity The credential entity to update
     * @param dto    The credential DTO with new values
     * @return The updated credential entity
     */
    public Credential updateEntityFromDTO(Credential entity, CredentialDTO dto) {
        if (entity == null || dto == null) {
            return entity;
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

        if (dto.getDomainId() != null) {
            entity.setDomainId(dto.getDomainId());
        }

        if (dto.getFavoriteSpecified()) {
            entity.setFavorite(dto.isFavorite() ? String.valueOf(Boolean.TRUE) : String.valueOf(Boolean.FALSE));
        }

        return entity;
    }
}