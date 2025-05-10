package com.lockbox.api;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.domain.DomainListResponseDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.dto.domain.DomainResponseDTO;
import com.lockbox.service.domain.DomainService;
import com.lockbox.utils.ExceptionBuilder;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    @Autowired
    private DomainService domainService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<DomainListResponseDTO> getAllDomains() {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainListResponseDTO domainListResponse = domainService.findAllDomainsByUser(userId);
            ResponseEntityBuilder<DomainListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch domains").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> getDomainById(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.findDomainById(id, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to fetch domain").throwInternalServerErrorException();
            return null;
        }
    }

    @PostMapping
    public ResponseEntityDTO<DomainResponseDTO> createDomain(@RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.createDomain(requestDTO, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to create domain").throwInternalServerErrorException();
            return null;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntityDTO<DomainResponseDTO> updateDomain(@PathVariable String id,
            @RequestBody DomainRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.updateDomain(id, requestDTO, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to update domain").throwInternalServerErrorException();
            return null;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntityDTO<Void> deleteDomain(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            domainService.deleteDomain(id, userId);
            ResponseEntityBuilder<Void> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to delete domain").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/{id}/credentials")
    public ResponseEntityDTO<Integer> getCredentialCountInDomain(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            int count = domainService.getCredentialCountInDomain(id, userId);
            ResponseEntityBuilder<Integer> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(count).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to get credential count").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/verify")
    public ResponseEntityDTO<DomainResponseDTO> verifyDomainByUrl(@RequestParam String url) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainResponseDTO domainResponse = domainService.verifyDomainByUrl(url, userId);
            ResponseEntityBuilder<DomainResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to verify domain").throwInternalServerErrorException();
            return null;
        }
    }

    @GetMapping("/search")
    public ResponseEntityDTO<DomainListResponseDTO> searchDomains(@RequestParam String query) {
        try {
            String userId = securityUtils.getCurrentUserId();
            DomainListResponseDTO domainListResponse = domainService.searchDomainsByName(query, userId);
            ResponseEntityBuilder<DomainListResponseDTO> responseBuilder = new ResponseEntityBuilder<>();
            return responseBuilder.setData(domainListResponse).build();
        } catch (Exception e) {
            ExceptionBuilder.create().setMessage("Failed to search domains").throwInternalServerErrorException();
            return null;
        }
    }
}