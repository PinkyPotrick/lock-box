package com.lockbox.service.domain;

import java.util.Optional;

import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.model.Domain;

public interface DomainService {

    DomainListResponseDTO findAllDomainsByUser(String userId, Integer page, Integer size) throws Exception;

    DomainResponseDTO findDomainById(String id, String userId) throws Exception;

    DomainResponseDTO createDomain(DomainRequestDTO requestDTO, String userId) throws Exception;

    DomainResponseDTO updateDomain(String id, DomainRequestDTO requestDTO, String userId) throws Exception;

    void deleteDomain(String id, String userId) throws Exception;

    int getCredentialCountForDomain(String domainId, String userId) throws Exception;

    boolean isDomainOwnedByUser(String domainId, String userId) throws Exception;

    Optional<Domain> findById(String id) throws Exception;

    int countByUserId(String userId);
}