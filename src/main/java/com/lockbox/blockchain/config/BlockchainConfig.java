package com.lockbox.blockchain.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;

import com.lockbox.blockchain.contract.CredentialVerifier;

@Configuration
@ConditionalOnProperty(name = "blockchain.feature.enabled", havingValue = "true")
public class BlockchainConfig {

    private static final Logger logger = LoggerFactory.getLogger(BlockchainConfig.class);

    @Value("${blockchain.ethereum.url:http://127.0.0.1:7545}")
    private String ethereumNodeUrl;

    @Value("${blockchain.contract.address}")
    private String contractAddress;

    @Value("${blockchain.wallet.private-key}")
    private String walletPrivateKey;

    @Bean
    public Web3j web3j() {
        logger.info("Initializing Web3j with Ethereum node at: {}", ethereumNodeUrl);
        return Web3j.build(new HttpService(ethereumNodeUrl));
    }

    @Bean
    public Credentials credentials() {
        logger.info("Loading wallet credentials for blockchain transactions");
        return Credentials.create(walletPrivateKey);
    }

    @Bean
    public CredentialVerifier credentialVerifier(Web3j web3j, Credentials credentials) {
        logger.info("Loading CredentialVerifier contract at address: {}", contractAddress);
        return CredentialVerifier.load(contractAddress, web3j, credentials, CredentialVerifier.GAS_PRICE,
                CredentialVerifier.GAS_LIMIT);
    }
}