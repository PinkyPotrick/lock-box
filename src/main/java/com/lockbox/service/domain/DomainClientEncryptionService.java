package com.lockbox.service.domain;

import java.util.List;

import com.lockbox.dto.domain.DomainDTO;
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;

public interface DomainClientEncryptionService {

    DomainResponseDTO encryptDomainForClient(DomainDTO domainDTO) throws Exception;

    DomainListResponseDTO encryptDomainListForClient(List<DomainDTO> domainDTOs) throws Exception;

    DomainDTO decryptDomainFromClient(DomainRequestDTO requestDTO) throws Exception;
}