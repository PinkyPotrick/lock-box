package com.lockbox.utils;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;

public class DataTypesUtilsTest {

    @Test
    void testHexStringToByteArray_ValidHex() {
        String hex = "0a1b2c";
        byte[] result = DataTypesUtils.hexStringToByteArray(hex);
        assertNotNull(result);
        assertEquals(3, result.length);
    }

    @Test
    void testHexStringToByteArray_InvalidHex() {
        String invalidHex = "abc"; // Odd length
        assertThrows(IllegalArgumentException.class, () -> {
            DataTypesUtils.hexStringToByteArray(invalidHex);
        });
    }

    @Test
    void testRemoveLeadingZeros() {
        byte[] data = { 0, 0, 1, 2 };
        byte[] trimmed = DataTypesUtils.removeLeadingZeros(data);
        assertArrayEquals(new byte[] { 1, 2 }, trimmed);
    }

    @Test
    void testBytesToHex() {
        byte[] data = { 10, 27, 44 };
        String hex = DataTypesUtils.bytesToHex(data);
        assertEquals("0a1b2c", hex);
    }

    @Test
    void testToFixedLengthByteArray() {
        BigInteger value = BigInteger.valueOf(255);
        byte[] fixed = DataTypesUtils.toFixedLengthByteArray(value, 4);
        assertEquals(4, fixed.length);
    }

    @Test
    void testToHexString() {
        byte[] data = { 10, 27, 44 };
        String hex = DataTypesUtils.toHexString(data);
        assertEquals("0a1b2c", hex);
    }
}