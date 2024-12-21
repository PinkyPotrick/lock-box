package com.lockbox.utils;

import java.math.BigInteger;
import java.util.Arrays;

public class DataTypesUtils {
    /**
     * Converts a hex string to a byte array.
     *
     * @param hexString - The hex string to convert.
     * @return The byte array representation of the hex string.
     */
    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Removes leading zeros from a byte array.
     *
     * @param bytes The byte array.
     * @return A new byte array with leading zeros removed.
     */
    public static byte[] removeLeadingZeros(byte[] bytes) {
        int start = 0;
        while (start < bytes.length && bytes[start] == 0) {
            start++;
        }
        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    /**
     * Converts a byte array to a hex string.
     *
     * @param bytes The byte array.
     * @return The hex string representation of the byte array.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append("%02x".formatted(b));
        }
        return sb.toString();
    }

    /**
     * Converts a BigInteger value to a fixed-length byte array.
     * 
     * @param value  - The BigInteger value to convert.
     * @param length - The desired length of the byte array.
     * @return A byte array of the specified length, padded with leading zeros if necessary.
     */
    public static byte[] toFixedLengthByteArray(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] padded = new byte[length];
        System.arraycopy(bytes, Math.max(0, bytes.length - length), padded, Math.max(0, length - bytes.length),
                Math.min(length, bytes.length));
        return padded;
    }

    /**
     * Converts a byte array to its hexadecimal string representation.
     * 
     * @param bytes - The byte array to convert.
     * @return The hexadecimal string representation of the byte array.
     */
    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append("%02x".formatted(b));
        }
        return sb.toString();
    }
}
