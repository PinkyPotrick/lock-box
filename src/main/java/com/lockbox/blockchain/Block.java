package com.lockbox.blockchain;

import java.security.MessageDigest;
import java.util.Date;

public class Block {
    private int id;
    private int nonce;  
    private long timestamp;
    private String previousHash;
    private String hash;
    private String data;

    public Block(int id, String data, String previousHash) {
        this.id = id;
        this.timestamp = new Date().getTime();
        this.data = data;
        this.previousHash = previousHash;
        this.hash = generateHash();
    }

    public String generateHash() {
        String input = Integer.toString(id) + previousHash + Long.toString(timestamp) + Integer.toString(nonce) + data;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append("%02x".formatted(b));
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getNonce() {
        return nonce;
    }

    public void setNonce(int nonce) {
        this.nonce = nonce;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }
  
    public void incrementNonce() {  
        this.nonce++;  
    }  
}
