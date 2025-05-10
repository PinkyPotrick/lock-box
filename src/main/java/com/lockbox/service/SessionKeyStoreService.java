package com.lockbox.service;

import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.lockbox.utils.AppConstants.SessionKeyAttributes;

import jakarta.servlet.http.HttpSession;

/**
 * Service for securely storing and retrieving encryption keys in the user's session
 */
@Service
public class SessionKeyStoreService {

    /**
     * Store encryption keys in the session
     * 
     * @param publicKeyPem User's public key PEM
     * @param privateKey   User's private key (usually encrypted)
     * @param aesKey       User's AES key
     */
    public void storeUserKeys(String publicKeyPem, String privateKey, String aesKey) {
        HttpSession session = getSession();
        session.setAttribute(SessionKeyAttributes.USER_PUBLIC_KEY, publicKeyPem);
        session.setAttribute(SessionKeyAttributes.USER_PRIVATE_KEY, privateKey);
        session.setAttribute(SessionKeyAttributes.USER_AES_KEY, aesKey);
    }

    /**
     * Get the user's public key from the session
     * 
     * @return User's public key PEM
     */
    public String getUserPublicKey() {
        return (String) getSession().getAttribute(SessionKeyAttributes.USER_PUBLIC_KEY);
    }

    /**
     * Get the user's private key from the session
     * 
     * @return User's private key
     */
    public String getUserPrivateKey() {
        return (String) getSession().getAttribute(SessionKeyAttributes.USER_PRIVATE_KEY);
    }

    /**
     * Get the user's AES key from the session
     * 
     * @return User's AES key
     */
    public String getUserAesKey() {
        return (String) getSession().getAttribute(SessionKeyAttributes.USER_AES_KEY);
    }

    /**
     * Clear all encryption keys from the session
     */
    public void clearUserKeys() {
        HttpSession session = getSession();
        session.removeAttribute(SessionKeyAttributes.USER_PUBLIC_KEY);
        session.removeAttribute(SessionKeyAttributes.USER_PRIVATE_KEY);
        session.removeAttribute(SessionKeyAttributes.USER_AES_KEY);
    }

    /**
     * Helper method to get the current HTTP session
     * 
     * @return The current HTTP session
     */
    private HttpSession getSession() {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        return attr.getRequest().getSession(true);
    }
}