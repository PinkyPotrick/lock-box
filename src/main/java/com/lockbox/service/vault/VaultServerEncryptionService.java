package com.lockbox.service.vault;

import com.lockbox.model.Vault;

public interface VaultServerEncryptionService {

    Vault encryptServerData(Vault vault) throws Exception;

    Vault decryptServerData(Vault vault) throws Exception;
}