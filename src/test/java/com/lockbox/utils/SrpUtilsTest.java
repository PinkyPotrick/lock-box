package com.lockbox.utils;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class SrpUtilsTest {

    @Test
    void testGenerateRandomPrivateValue() {
        SrpUtils utils = new SrpUtils();
        BigInteger value = utils.generateRandomPrivateValue();
        assertNotNull(value);
        assertTrue(value.compareTo(BigInteger.ZERO) > 0);
    }

    @Test
    void testComputeB() {
        SrpUtils utils = new SrpUtils();
        BigInteger v = BigInteger.valueOf(12345);
        BigInteger b = BigInteger.valueOf(6789);
        BigInteger result = utils.computeB(v, b);
        assertNotNull(result);
    }

    @Test
    void testComputeU() throws NoSuchAlgorithmException {
        SrpUtils utils = new SrpUtils();
        BigInteger B = BigInteger.valueOf(123456789);
        BigInteger u = utils.computeU(B);
        assertNotNull(u);
    }

    @Test
    void testComputeS() {
        SrpUtils utils = new SrpUtils();
        BigInteger A = BigInteger.valueOf(11111);
        BigInteger v = BigInteger.valueOf(22222);
        BigInteger u = BigInteger.valueOf(33333);
        BigInteger b = BigInteger.valueOf(44444);
        BigInteger S = utils.computeS(A, v, u, b);
        assertNotNull(S);
    }

    @Test
    void testComputeK() throws NoSuchAlgorithmException {
        SrpUtils utils = new SrpUtils();
        BigInteger S = BigInteger.valueOf(55555);
        String K = utils.computeK(S);
        assertNotNull(K);
        assertFalse(K.isEmpty());
    }

    @Test
    void testComputeM1() throws NoSuchAlgorithmException {
        SrpUtils utils = new SrpUtils();
        String M1 = utils.computeM1("testUser", "salt", BigInteger.ONE, BigInteger.TEN, "sessionKey");
        assertNotNull(M1);
        assertFalse(M1.isEmpty());
    }

    @Test
    void testComputeM2() throws NoSuchAlgorithmException {
        SrpUtils utils = new SrpUtils();
        String M2 = utils.computeM2(BigInteger.ONE, "testM1", "sessionKey");
        assertNotNull(M2);
        assertFalse(M2.isEmpty());
    }
}