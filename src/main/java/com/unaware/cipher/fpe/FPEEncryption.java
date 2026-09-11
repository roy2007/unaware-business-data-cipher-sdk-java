package com.unaware.cipher.fpe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

/**
 * FPE（格式保留加密）算法实现类
 *
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 */
public class FPEEncryption {

    private final static Logger logger = LoggerFactory.getLogger(FPEEncryption.class);

    // 支持的默认字符集常量
    private static final String DEFAULT_CHARSET = "0123456789";
    private static final int DEFAULT_TWEAK_SIZE = 8;
    private final String charset;
    private final int radix;
    // AES block size
    private final int blockSize = 128;
    private final byte[] key; // AES密钥

    /**
     * 构造函数，使用默认字符集（数字）和密钥
     * @param key AES密钥（16/24/32字节）
     */
    public FPEEncryption(byte[] key) {
        this(key, DEFAULT_CHARSET);
    }

    /**
     * 构造函数，使用自定义字符集和密钥
     *
     * @param key     AES密钥（16/24/32字节）
     * @param charset 字符集
     */
    public FPEEncryption(byte[] key, String charset) {
        // 验证密钥长度
        if (key == null || !(key.length == 16 || key.length == 24)) {
            logger.warn("Invalid AES key length: must be 16, 24, or 32 bytes, but got：{} ", (key != null ? key.length : "null"));
            key = "FPESecretKey1234".getBytes();
        }
        // 确保字符集非空且不包含重复字符
        if (null == charset || charset.isEmpty()) {
            logger.warn("字符集不能为空，使用默认字符集");
            charset = DEFAULT_CHARSET;
        }
        this.key = key.clone();
        this.charset = charset;
        this.radix = charset.length();
        if (radix < 2 || radix > 65536) {
            throw new IllegalArgumentException("Radix out of range [2, 65536]: " + radix);
        }
    }

    /**
     * FPE加密
     *
     * @param plaintext 明文
     * @param tweak     调整值
     * @return 密文
     * @throws Exception 加密异常
     */
    public String encrypt(String plaintext, byte[] tweak) throws Exception {
        if (plaintext == null || plaintext.isEmpty()) {
            return plaintext;
        }
        // 确保tweak长度正确
        byte[] validTweak = validateTweak(tweak);

        // 将明文转换为数字
        BigInteger x = stringToNumber(plaintext, charset);
        BigInteger n = BigInteger.valueOf(radix).pow(plaintext.length());

        // 使用FF1算法进行加密
        BigInteger y = ff1Encrypt(x, n, validTweak);

        // 将数字转换回字符串
        return numberToString(y, charset, plaintext.length());
    }

    /**
     * FPE解密
     *
     * @param ciphertext 密文
     * @param tweak      调整值
     * @return 明文
     * @throws Exception 解密异常
     */
    public String decrypt(String ciphertext, byte[] tweak) throws Exception {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return ciphertext;
        }
        // 确保tweak长度正确
        byte[] validTweak = validateTweak(tweak);
        // 将密文转换为数字
        BigInteger y = stringToNumber(ciphertext, charset);
        BigInteger n = BigInteger.valueOf(radix).pow(ciphertext.length());
        // 使用FF1算法进行解密
        BigInteger x = ff1Decrypt(y, n, validTweak);
        // 将数字转换回字符串
        return numberToString(x, charset, ciphertext.length());
    }

    private BigInteger ff1Encrypt(BigInteger x, BigInteger n, byte[] tweak) throws Exception {
        int originalLen = calculateLength(n);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        aes.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // 构造 P（一次即可）
        byte[] P = buildP(tweak, originalLen);

        // 主循环（正序：0 → 9）
        for (int i = 0; i < 10; i++) {
            int u = (originalLen + 1) / 2;
            int v = originalLen - u;

            // 分割 x 为 A (高u位) 和 B (低v位)
            BigInteger c = BigInteger.valueOf(radix).pow(v);
            BigInteger A = x.divide(c);
            BigInteger B = x.mod(c);

            // 构造 Q
            byte[] Q = buildQ(P, B, i);

            // 补齐到 16 字节的倍数
            byte[] paddedQ = padToBlocksize(Q, 16);

            // 计算 R = AES(K, paddedQ)
            byte[] R_full = aes.doFinal(paddedQ);

            // 提取 d 字节
            int d = (int) Math.ceil((v * Math.log(radix)) / Math.log(2) / 8.0);
            if (d > R_full.length) d = R_full.length; // 防止越界
            byte[] S = Arrays.copyOf(R_full, d); // 前 d 字节

            // 计算 C = (B + S) mod radix^v
            BigInteger S_num = new BigInteger(1, S);
            BigInteger C = B.add(S_num).mod(c);

            // 更新 x = C * radix^u + A
            x = C.multiply(BigInteger.valueOf(radix).pow(u)).add(A);
        }

        return x;
    }

    private BigInteger ff1Decrypt1(BigInteger y, BigInteger n, byte[] tweak) throws Exception {
        int originalLen = calculateLength(n);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        aes.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // 构造 P（一次即可）
        byte[] P = buildP(tweak, originalLen);

        // 主循环（逆序：9 → 0）
        for (int i = 9; i >= 0; i--) {
            int u = (originalLen + 1) / 2;
            int v = originalLen - u;

            // 分割 y 为 A (高u位) 和 B (低v位)
            BigInteger c = BigInteger.valueOf(radix).pow(v);
            BigInteger A = y.divide(c);
            BigInteger B = y.mod(c);

            // 构造 Q
            byte[] Q = buildQ(P, B, i);

            // 补齐到 16 字节的倍数
            byte[] paddedQ = padToBlocksize(Q, 16);

            // 计算 R = AES(K, paddedQ)
            byte[] R_full = aes.doFinal(paddedQ);

            // 提取 d 字节
            int d = (int) Math.ceil((v * Math.log(radix)) / Math.log(2) / 8.0);
            if (d > R_full.length) d = R_full.length; // 防止越界
            byte[] S = Arrays.copyOf(R_full, d); // 前 d 字节

            // 计算 C = (B - S) mod radix^v
            BigInteger S_num = new BigInteger(1, S);
            BigInteger C = B.subtract(S_num).mod(c);

            // 更新 y = C * radix^u + A
            y = C.multiply(BigInteger.valueOf(radix).pow(u)).add(A);
        }

        return y;
    }

    private BigInteger ff1Decrypt(BigInteger y, BigInteger n, byte[] tweak) throws Exception {
        int originalLen = calculateLength(n);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        aes.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] P = buildP(tweak, originalLen);

        for (int i = 9; i >= 0; i--) {
            int u = (originalLen + 1) / 2; // ceil(n/2)
            int v = originalLen - u;       // floor(n/2)

            // 关键：y = C * radix^u + A
            BigInteger radixU = BigInteger.valueOf(radix).pow(u);
            BigInteger A = y.mod(radixU);          // A = low u digits
            BigInteger C = y.divide(radixU);       // C = high v digits

            // 构造 Q 使用 A（即加密时的 A）
            byte[] Q = buildQ(P, A, i);

            byte[] paddedQ = padToBlocksize(Q, 16);
            byte[] R_full = aes.doFinal(paddedQ);

            int d = (int) Math.ceil((v * Math.log(radix)) / Math.log(2) / 8.0);
            if (d > R_full.length) d = R_full.length;
            byte[] S = Arrays.copyOf(R_full, d);
            BigInteger S_num = new BigInteger(1, S);

            // 计算 B = (C - S) mod radix^v
            BigInteger radixV = BigInteger.valueOf(radix).pow(v);
            BigInteger B = C.subtract(S_num).mod(radixV);

            // 重组上一轮的输入: x = A * radix^v + B
            y = A.multiply(radixV).add(B);
        }
        return y;
    }

    // ======== 工具方法 ========
    private int calculateLength(BigInteger n) {
        // n = radix^L => L = log_radix(n)
        int L = 0;
        BigInteger tmp = n;
        while (tmp.compareTo(BigInteger.ONE) > 0) {
            tmp = tmp.divide(BigInteger.valueOf(radix));
            L++;
        }
        return L;
    }

    private byte[] buildP(byte[] tweak, int len) {
        ByteBuffer bb = ByteBuffer.allocate(1 + 1 + 1 + tweak.length + 4 + 4);
        bb.put((byte) 1); // version
        bb.put((byte) (blockSize / 8)); // m (16 for AES)
        bb.put((byte) tweak.length);
        bb.put(tweak);
        bb.putInt(radix); // radix as 4-byte big-endian
        bb.putInt(len);   // length as 4-byte big-endian
        return bb.array();
    }

    private byte[] buildQ(byte[] P, BigInteger B, int i) {
        byte[] B_bytes = toMinimalByteArray(B);
        ByteBuffer bb = ByteBuffer.allocate(P.length + B_bytes.length + 1);
        bb.put(P);
        bb.put(B_bytes);
        bb.put((byte) i);
        return bb.array();
    }

    // 将 BigInteger 转为最小字节数组（无前导零）
    private byte[] toMinimalByteArray(BigInteger value) {
        if (value.equals(BigInteger.ZERO)) return new byte[]{0};
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    // 补齐到 blocksize 的倍数
    private byte[] padToBlocksize(byte[] data, int blocksize) {
        int remainder = data.length % blocksize;
        if (remainder == 0) {
            return data;
        }
        int padding = blocksize - remainder;
        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);
        // 填充 0
        return padded;
    }

    /**
     * 将字符串转换为数字
     *
     * @param str     字符串
     * @param charset 字符集
     * @return 数字
     */
    private BigInteger stringToNumber(String str, String charset) {
        BigInteger result = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(charset.length());

        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            int index = charset.indexOf(c);
            if (index == -1) {
                throw new IllegalArgumentException("Character not in charset: " + c);
            }
            result = result.multiply(base).add(BigInteger.valueOf(index));
        }

        return result;
    }

    /**
     * 将数字转换为字符串
     *
     * @param num     数字
     * @param charset 字符集
     * @param length  字符串长度
     * @return 字符串
     */
    private String numberToString(BigInteger num, String charset, int length) {
        if (num.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Negative number not allowed");
        }

        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(charset.length());
        BigInteger value = num;

        // 特殊处理0
        if (value.equals(BigInteger.ZERO)) {
            for (int i = 0; i < length; i++) sb.append(charset.charAt(0));
            return sb.toString();
        }

        // 转换
        while (value.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divMod = value.divideAndRemainder(base);
            int remainder = divMod[1].intValue();
            sb.append(charset.charAt(remainder));
            value = divMod[0];
        }

        // 补前导零
        while (sb.length() < length) {
            sb.append(charset.charAt(0));
        }

        return sb.reverse().toString();
    }

    /**
     * 验证并调整tweak的长度
     *
     * @param tweak 原始tweak
     * @return 调整后的tweak
     */
    private byte[] validateTweak(byte[] tweak) {
        if (tweak == null) {
            return generateRandomTweak();
        }

        if (tweak.length == DEFAULT_TWEAK_SIZE) {
            return tweak;
        }

        // 调整tweak长度
        byte[] validTweak = new byte[DEFAULT_TWEAK_SIZE];
        if (tweak.length < DEFAULT_TWEAK_SIZE) {
            System.arraycopy(tweak, 0, validTweak, 0, tweak.length);
            // 填充0
        } else {
            System.arraycopy(tweak, 0, validTweak, 0, DEFAULT_TWEAK_SIZE);
        }
        return validTweak;
    }

    /**
     * 生成随机tweak
     *
     * @return 随机tweak
     */
    public byte[] generateRandomTweak() {
        byte[] tweak = new byte[DEFAULT_TWEAK_SIZE];
        new SecureRandom().nextBytes(tweak);
        return tweak;
    }

    private static void validateInput(String alphabet, String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }
        for (char c : input.toCharArray()) {
            if (alphabet.indexOf(c) == -1) {
                throw new IllegalArgumentException("Character '" + c + "' not in alphabet");
            }
        }
    }

    // ======== 测试用例 ========
    public static void main(String[] args) {
        try {
            byte[] tweak = "test".getBytes();
            {
                FPEEncryption fpe = new FPEEncryption(null, "0123456789");
                String plaintext = "12345678";
                String ciphertext = fpe.encrypt(plaintext, tweak);
                System.out.println("Original: " + plaintext);
                System.out.println("Encrypted: " + ciphertext);

                String decrypted = fpe.decrypt(ciphertext, tweak);
                System.out.println("Decrypted: " + decrypted);

                assert plaintext.equals(decrypted);
                System.out.println("加解密成功！");
            }
            {
                FPEEncryption fpe = new FPEEncryption(null, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-.~+=_");
                String plaintext = "yadADfi-+efadd";
                String ciphertext = fpe.encrypt(plaintext, tweak);
                System.out.println("Original: " + plaintext);
                System.out.println("Encrypted: " + ciphertext);

                String decrypted = fpe.decrypt(ciphertext, tweak);
                System.out.println("Decrypted: " + decrypted);

                assert plaintext.equals(decrypted);
                System.out.println("加解密成功！");
            }
            {
                FPEEncryption fpe = new FPEEncryption(null, "01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-.~+=_");
                String plaintext = "010-64524861";
                String ciphertext = fpe.encrypt(plaintext, tweak);
                System.out.println("Original: " + plaintext);
                System.out.println("Encrypted: " + ciphertext);

                String decrypted = fpe.decrypt(ciphertext, tweak);
                System.out.println("Decrypted: " + decrypted);

                assert plaintext.equals(decrypted);
                System.out.println("加解密成功！");
            }

            {
                FPEEncryption fpe = new FPEEncryption(null, "0123456789");
                String plaintext = "13439298452";
                String ciphertext = fpe.encrypt(plaintext, tweak);
                System.out.println("Original: " + plaintext);
                System.out.println("Encrypted: " + ciphertext);

                String decrypted = fpe.decrypt(ciphertext, tweak);
                System.out.println("Decrypted: " + decrypted);

                assert plaintext.equals(decrypted);
                System.out.println("加解密成功！");
            }
        } catch (Exception e) {
            logger.error("执行FPE加解密测试main函数发生异常, 参数: {}", args, e);
        }
    }
}