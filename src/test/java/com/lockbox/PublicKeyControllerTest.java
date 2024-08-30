package com.lockbox;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class PublicKeyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testGetPublicKey() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/auth/public-key"))
               .andExpect(status().isOk());
    }
}
