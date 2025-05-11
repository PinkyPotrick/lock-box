package com.lockbox.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Credential;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, String> {

    List<Credential> findByVaultId(String vaultId);

    Page<Credential> findByVaultId(String vaultId, Pageable pageable);

    @Query(value = "SELECT c FROM Credential c LEFT JOIN Domain d ON c.domainId = d.id "
            + "WHERE c.vaultId = :vaultId ORDER BY d.name")
    Page<Credential> findByVaultIdOrderByDomainName(@Param("vaultId") String vaultId, Pageable pageable);

    @Query(value = "SELECT c FROM Credential c LEFT JOIN Domain d ON c.domainId = d.id "
            + "WHERE c.vaultId = :vaultId ORDER BY d.name ASC")
    Page<Credential> findByVaultIdOrderByDomainNameAsc(@Param("vaultId") String vaultId, Pageable pageable);

    @Query(value = "SELECT c FROM Credential c LEFT JOIN Domain d ON c.domainId = d.id "
            + "WHERE c.vaultId = :vaultId ORDER BY d.name DESC")
    Page<Credential> findByVaultIdOrderByDomainNameDesc(@Param("vaultId") String vaultId, Pageable pageable);

    int countByVaultId(String vaultId);

    List<Credential> findByUserId(String userId);

    Page<Credential> findByUserId(String userId, Pageable pageable);

    List<Credential> findByUserIdAndFavorite(String userId, String favorite);

    List<Credential> findByDomainIdAndUserId(String domainId, String userId);

    int countByDomainIdAndUserId(String domainId, String userId);

    int countByUserId(String userId);

    int countByDomainId(String domainId);

    int deleteByVaultId(String vaultId);
}