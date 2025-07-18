package com.lockbox.service;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyStoreServiceTest {

    @InjectMocks
    private SessionKeyStoreService sessionKeyStore;

    private MockHttpServletRequest request;

    @SuppressWarnings("unused")
    private HttpSession session;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Create mock request and session
        request = new MockHttpServletRequest();
        session = request.getSession(true);

        // Set up RequestContextHolder
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    @Test
    void testStoreAndRetrieveUserKeys() {
        // Given
        String testPublicKey = "test-public-key";
        String testPrivateKey = "test-private-key";
        String testAesKey = "test-aes-key";

        // When
        sessionKeyStore.storeUserKeys(testPublicKey, testPrivateKey, testAesKey);

        // Then
        assertEquals(testPublicKey, sessionKeyStore.getUserPublicKey());
        assertEquals(testPrivateKey, sessionKeyStore.getUserPrivateKey());
        assertEquals(testAesKey, sessionKeyStore.getUserAesKey());
    }

    @Test
    void testClearUserKeys() {
        // Given
        sessionKeyStore.storeUserKeys("public", "private", "aes");

        // When
        sessionKeyStore.clearUserKeys();

        // Then
        assertNull(sessionKeyStore.getUserPublicKey());
        assertNull(sessionKeyStore.getUserPrivateKey());
        assertNull(sessionKeyStore.getUserAesKey());
    }
}