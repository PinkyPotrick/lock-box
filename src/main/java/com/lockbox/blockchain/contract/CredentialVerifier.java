package com.lockbox.blockchain.contract;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;

import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.gas.StaticGasProvider;

/**
 * Simplified manual implementation of the CredentialVerifier contract wrapper. This is a temporary solution
 */
public class CredentialVerifier extends Contract {

    public static final BigInteger GAS_PRICE = BigInteger.valueOf(20_000_000_000L);
    public static final BigInteger GAS_LIMIT = BigInteger.valueOf(4_300_000L);

    protected CredentialVerifier(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice,
            BigInteger gasLimit) {
        super("", contractAddress, web3j, credentials, new StaticGasProvider(gasPrice, gasLimit));
    }

    public static CredentialVerifier load(String contractAddress, Web3j web3j, Credentials credentials,
            BigInteger gasPrice, BigInteger gasLimit) {
        return new CredentialVerifier(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    public TransactionReceipt storeCredentialHashSync(String credentialId, String hash) throws Exception {
        final Function function = new Function("storeCredentialHash",
                Arrays.asList(new Utf8String(credentialId), new Utf8String(hash)), Collections.emptyList());

        return executeRemoteCallTransaction(function).send();
    }

    public CompletableFuture<TransactionReceipt> storeCredentialHash(String credentialId, String hash) {
        final Function function = new Function("storeCredentialHash",
                Arrays.asList(new Utf8String(credentialId), new Utf8String(hash)), Collections.emptyList());

        return executeRemoteCallTransaction(function).sendAsync();
    }

    public RemoteCall<Boolean> verifyCredentialHash(String credentialId, String hash) {
        Function function = new Function("verifyCredentialHash",
                Arrays.asList(new Utf8String(credentialId), new Utf8String(hash)),
                Arrays.asList(new TypeReference<Bool>() {
                }));
        return executeRemoteCallSingleValueReturn(function, Boolean.class);
    }

    public RemoteCall<String> getCredentialHash(String credentialId) {
        Function function = new Function("getCredentialHash", Collections.singletonList(new Utf8String(credentialId)),
                Arrays.asList(new TypeReference<Utf8String>() {
                }));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteCall<BigInteger> getLastUpdated(String credentialId) {
        Function function = new Function("getLastUpdated", Collections.singletonList(new Utf8String(credentialId)),
                Arrays.asList(new TypeReference<Uint256>() {
                }));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public Web3j getWeb3j() {
        return this.web3j;
    }
}