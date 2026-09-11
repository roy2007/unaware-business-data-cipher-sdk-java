package com.unaware.cipher.common.utils;

/**
 * @author: Roy rui wang
 * @data 2026年01月14日 15:33
 */
public class HexUtils {
    private static final char[] HEX_DIGITS_LOWER = "0123456789abcdef".toCharArray();
    private static final char[] HEX_DIGITS_UPPER = "0123456789ABCDEF".toCharArray();

    // 禁止实例化
    private HexUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * 将 byte[] 转换为小写十六进制字符串
     *
     * @param bytes 输入字节数组（可为 null）
     * @return 十六进制字符串，若输入为 null 则返回 null
     */
    public static String encode(byte[] bytes) {
        return encode(bytes, false);
    }

    /**
     * 将 byte[] 转换为十六进制字符串
     *
     * @param bytes     输入字节数组（可为 null）
     * @param uppercase 是否使用大写字母
     * @return 十六进制字符串，若输入为 null 则返回 null
     */
    public static String encode(byte[] bytes, boolean uppercase) {
        if (bytes == null) {
            return null;
        }
        if (bytes.length == 0) {
            return "";
        }
        char[] digits = uppercase ? HEX_DIGITS_UPPER : HEX_DIGITS_LOWER;
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = digits[v >>> 4];
            hexChars[i * 2 + 1] = digits[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * 将十六进制字符串解析为 byte[]
     *
     * @param hex 十六进制字符串（可为 null，允许包含空白字符）
     * @return 字节数组，若输入为 null 或空则返回 null 或空数组
     * @throws IllegalArgumentException 如果字符串包含非法十六进制字符或长度为奇数
     */
    public static byte[] decode(String hex) {
        if (hex == null) {
            return null;
        }
        // 去除所有空白字符（包括空格、换行、制表符等）
        String cleanHex = hex.replaceAll("\\s+", "");
        if (cleanHex.isEmpty()) {
            return new byte[0];
        }
        if (cleanHex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string: odd length - " + hex);
        }

        byte[] bytes = new byte[cleanHex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(cleanHex.charAt(i * 2), 16);
            int low = Character.digit(cleanHex.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hex character at index " + (i * 2) + " in: " + hex);
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    /**
     * 判断字符串是否为有效的十六进制格式（忽略空白）
     *
     * @param hex 待检测字符串
     * @return true 如果是有效 hex（包括 null 或空字符串）
     */
    public static boolean isValidHex(String hex) {
        if (hex == null || hex.isEmpty()) {
            return true;
        }
        String clean = hex.replaceAll("\\s+", "");
        if (clean.isEmpty()) {
            return true;
        }
        if (clean.length() % 2 != 0) {
            return false;
        }
        for (char c : clean.toCharArray()) {
            if (!Character.isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F')) {
                return false;
            }
        }
        return true;
    }
}
