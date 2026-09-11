package com.unaware.cipher.derivation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * 密钥派生类，负责从根密钥派生出各业务模块专用密钥
 * @author wanj7
 * @version 1.0
 * @since 2024-12-15
 */
public class KeyDerivation {
    private static final Logger logger = LoggerFactory.getLogger(KeyDerivation.class);

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int DEFAULT_KEY_LENGTH = 256;

    // Base62 字符集：0-9, A-Z, a-z
    private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int DEFAULT_PASSWORD_LENGTH = 8;

    /**
     * 从根密钥派生业务模块专用密钥
     *
     * @param rootKey          根密钥
     * @param subjectDomain    主题域（业务模块标识）
     * @param keyVersion       密钥版本
     * @param keyLength        派生密钥长度（bits）
     * @return 派生的密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws InvalidKeyException      无效密钥异常
     */
    public static SecretKey deriveKey(SecretKey rootKey, String subjectDomain, int keyVersion, int keyLength) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        // 构建派生上下文
        String derivationContext = buildDerivationContext(subjectDomain, keyVersion);
        
        // 使用HKDF算法派生密钥
        byte[] derivedKeyBytes = hkdf(rootKey.getEncoded(), derivationContext.getBytes(), keyLength);
        
        // 创建AES密钥
        return new SecretKeySpec(derivedKeyBytes, "AES");
    }

    /**
     * 从根密钥派生业务模块专用密钥（使用默认密钥长度）
     *
     * @param rootKey          根密钥
     * @param subjectDomain    主题域（业务模块标识）
     * @param keyVersion       密钥版本
     * @return 派生的密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws InvalidKeyException      无效密钥异常
     */
    public static SecretKey deriveKey(SecretKey rootKey, String subjectDomain, int keyVersion) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        if(subjectDomain == null || subjectDomain.isEmpty()) {
            throw new IllegalArgumentException("主题域不能为空");
        }
        if(!rootKey.getAlgorithm().equals("AES")) {
            throw new IllegalArgumentException("根密钥必须是AES算法");
        }
        if(keyVersion <= 0) {
            throw new IllegalArgumentException("密钥版本必须大于0");
        }
        return deriveKey(rootKey, subjectDomain, keyVersion, DEFAULT_KEY_LENGTH);
    }

    /**
     * 构建密钥派生上下文
     *
     * @param subjectDomain    主题域
     * @param keyVersion       密钥版本
     * @return 派生上下文字符串
     */
    private static String buildDerivationContext(String subjectDomain, int keyVersion) {
        return String.format("yunwuye_DERIVATION_KEY|%s|VERSION_%d", subjectDomain, keyVersion);
    }

    /**
     * HKDF（HMAC-based Extract-and-Expand Key Derivation Function）实现
     *
     * @param ikm       输入密钥材料
     * @param info      上下文信息
     * @param keyLength 输出密钥长度（bits）
     * @return 派生的密钥字节数组
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws InvalidKeyException      无效密钥异常
     */
    private static byte[] hkdf(byte[] ikm, byte[] info, int keyLength) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        // Step 1: Extract
        byte[] prk = extract(ikm);
        
        // Step 2: Expand
        return expand(prk, info, keyLength);
    }

    /**
     * HKDF-Extract步骤：从输入密钥材料中提取固定长度的伪随机密钥
     *
     * @param ikm 输入密钥材料
     * @return 伪随机密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws InvalidKeyException      无效密钥异常
     */
    private static byte[] extract(byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
        // 使用空盐值（根据HKDF规范，空盐值等同于哈希算法输出长度的零字节数组）
        byte[] salt = new byte[MessageDigest.getInstance(HASH_ALGORITHM).getDigestLength()];
        Arrays.fill(salt, (byte) 0x00);
        
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec saltKey = new SecretKeySpec(salt, HMAC_ALGORITHM);
        mac.init(saltKey);
        return mac.doFinal(ikm);
    }

    /**
     * HKDF-Expand步骤：从伪随机密钥和上下文信息中扩展出所需长度的密钥
     *
     * @param prk       伪随机密钥
     * @param info      上下文信息
     * @param keyLength 输出密钥长度（bits）
     * @return 派生的密钥字节数组
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws InvalidKeyException      无效密钥异常
     */
    private static byte[] expand(byte[] prk, byte[] info, int keyLength) throws NoSuchAlgorithmException, InvalidKeyException {
        int hashLength = MessageDigest.getInstance(HASH_ALGORITHM).getDigestLength();
        int numBlocks = (int) Math.ceil((double) keyLength / (hashLength * 8));
        int outputLength = (keyLength + 7) / 8;
        
        if (numBlocks > 255) {
            throw new IllegalArgumentException("Requested key length is too long");
        }
        
        byte[] result = new byte[outputLength];
        byte[] current = new byte[0];
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec prkKey = new SecretKeySpec(prk, HMAC_ALGORITHM);
        mac.init(prkKey);
        
        int bytesCopied = 0;
        for (int i = 1; i <= numBlocks; i++) {
            // 更新MAC输入：前一个输出 | info | counter
            mac.reset();
            mac.update(current);
            mac.update(info);
            mac.update((byte) i);
            
            current = mac.doFinal();
            
            // 复制到结果数组
            int copyLength = Math.min(current.length, outputLength - bytesCopied);
            System.arraycopy(current, 0, result, bytesCopied, copyLength);
            bytesCopied += copyLength;
        }
        
        return result;
    }

    /**
     * 创建根密钥
     *
     * @param seed             种子数据
     * @param keyLength        根密钥长度（bits）
     * @return 根密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public static SecretKey createRootKey(byte[] seed, int keyLength) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hash = digest.digest(seed);
        
        // 如果需要更长的密钥，可以多次哈希并拼接
        if ((keyLength + 7) / 8 > hash.length) {
            MessageDigest digest2 = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hash2 = digest2.digest(hash);
            byte[] combined = new byte[hash.length + hash2.length];
            System.arraycopy(hash, 0, combined, 0, hash.length);
            System.arraycopy(hash2, 0, combined, hash.length, hash2.length);
            hash = combined;
        }
        
        // 截取所需长度
        byte[] keyBytes = Arrays.copyOf(hash, (keyLength + 7) / 8);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 创建根密钥（使用默认密钥长度）
     *
     * @param seed             种子数据
     * @return 根密钥
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public static SecretKey createRootKey(byte[] seed) throws NoSuchAlgorithmException {
        if (seed == null) {
            throw new IllegalArgumentException("Seed cannot be null");
        }
        if (seed.length < DEFAULT_KEY_LENGTH) {
            return createRootKey(seed, DEFAULT_KEY_LENGTH);
        }
        return createRootKey(seed, seed.length);
    }

    /**
     * 根据用户账号和年份派生指定长度密码
     * @param rootKey 根密钥
     * @param immutable 唯一不可变值
     * @param pwLength 密码长度
     * @return 8位字符串密码
     */
    public static String derivePassword(SecretKey rootKey, String immutable, int pwLength) {
        if (immutable == null || immutable.isEmpty()) {
            throw new IllegalArgumentException("immutable cannot be null or empty");
        }

        if (pwLength == 0) {
            pwLength = DEFAULT_PASSWORD_LENGTH;
        }
        try {
            int nextMultipleOf4 = (int) (Math.floor(pwLength / 4.0) + 1) * 4;
            int keyLength = estimateBitLengthByLength(nextMultipleOf4);
            String derivedPw = Base64.getEncoder().encodeToString((deriveKey(rootKey, immutable, 1, keyLength).getEncoded()));
            return derivedPw.length() > pwLength ? derivedPw.substring(0, pwLength) : derivedPw;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to derive password", e);
        }
    }

    private static String toBase62(byte[] bytes, int pwLength) {
        StringBuilder sb = new StringBuilder();
        long value = 0;
        for (int i = 0; i < Math.min(8, bytes.length); i++) {
            value = (value << 8) | (bytes[i] & 0xFF);
        }
        if (value == 0) {
            return "0";
        }
        while (value > 0) {
            sb.append(BASE62.charAt((int) (value % 62)));
            value /= 62;
        }

        String result = sb.reverse().toString();
        while (result.length() < pwLength) {
            result += result;
        }
        return result;
    }

    /**
     * 在假设无填充、无非法字符场景，根据 Base64后字符串长度快速估算密钥字节长度
     * 适用于已知是标准 Base64 且长度合规的场景
     *
     * @param base64Length Base64 字符串长度
     */
    public static int estimateBitLengthByLength(int base64Length) {
        if (base64Length < 0) {
            throw new IllegalArgumentException("Base64 length must be non-negative");
        }

        if (base64Length % 4 != 0) {
            logger.warn("标准 Base64长度不是4的倍数, 默认为8. base64Length: {}", base64Length);
            base64Length = 8;
        }

        long byteCount = (base64Length / 4L) * 3L;
        if (byteCount > 1024L) {
            logger.warn("Base64长度超出 int 能表示的 bit 范围, 默认为1024. base64Length: {}", base64Length);
            byteCount = 1024L;
        }
        return (int) (byteCount * 8);
    }
}