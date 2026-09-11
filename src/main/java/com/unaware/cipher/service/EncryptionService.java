package com.unaware.cipher.service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 标准加密算法服务类，提供AES、RSA和哈希算法功能
 */
public class EncryptionService {

    // AES算法相关常量
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
    public static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
    
    // RSA算法相关常量
    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
    
    // 哈希算法相关常量
    public static final String SHA256 = "SHA-256";
    public static final String SHA512 = "SHA-512";
    
    // HMAC算法相关常量
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final String HMAC_SHA512 = "HmacSHA512";


    /**
     * AES加密（CBC模式）
     *
     * @param plaintext        明文
     * @param secretKey        密钥
     * @param iv               初始化向量
     * @return 加密后的密文（Base64编码）
     * @throws Exception 加密异常
     */
    public static String aesEncryptCBC(String plaintext, SecretKey secretKey, byte[] iv) throws Exception {
        validateKeySize(iv);
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * AES解密（CBC模式）
     *
     * @param ciphertext       密文（Base64编码）
     * @param secretKey        密钥
     * @param iv               初始化向量
     * @return 解密后的明文
     * @throws Exception 解密异常
     */
    public static String aesDecryptCBC(String ciphertext, SecretKey secretKey, byte[] iv) throws Exception {
        validateKeySize(iv);
        Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * AES加密（ECB模式）
     *
     * @param plaintext        明文
     * @param secretKey        密钥
     * @return 加密后的密文（Base64编码）
     * @throws Exception 加密异常
     */
    public static String aesEncryptECB(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * AES解密（ECB模式）
     *
     * @param ciphertext       密文（Base64编码）
     * @param secretKey        密钥
     * @return 解密后的明文
     * @throws Exception 解密异常
     */
    public static String aesDecryptECB(String ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ECB_PKCS5);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * RSA加密
     *
     * @param plaintext        明文
     * @param publicKey        公钥
     * @return 加密后的密文（Base64编码）
     * @throws Exception 加密异常
     */
    public static String rsaEncrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * RSA解密
     *
     * @param ciphertext       密文（Base64编码）
     * @param privateKey       私钥
     * @return 解密后的明文
     * @throws Exception 解密异常
     */
    public static String rsaDecrypt(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * RSA数字签名生成
     *
     * @param data             数据
     * @param privateKey       私钥
     * @param signatureAlgorithm 签名算法
     * @return 签名（Base64编码）
     * @throws Exception 签名异常
     */
    public static String rsaSign(String data, PrivateKey privateKey, String signatureAlgorithm) throws Exception {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * RSA数字签名验证
     *
     * @param data             数据
     * @param signature        签名（Base64编码）
     * @param publicKey        公钥
     * @param signatureAlgorithm 签名算法
     * @return 验证结果
     * @throws Exception 验证异常
     */
    public static boolean rsaVerify(String data, String signature, PublicKey publicKey, String signatureAlgorithm) throws Exception {
        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(publicKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }

    /**
     * 哈希计算（SHA-256）
     *
     * @param data             数据
     * @return 哈希值（Base64编码）
     * @throws Exception 哈希计算异常
     */
    public static String hashSHA256(String data) throws Exception {
        return hash(data, SHA256);
    }

    /**
     * 哈希计算（SHA-512）
     *
     * @param data             数据
     * @return 哈希值（Base64编码）
     * @throws Exception 哈希计算异常
     */
    public static String hashSHA512(String data) throws Exception {
        return hash(data, SHA512);
    }

    /**
     * 通用哈希计算
     *
     * @param data             数据
     * @param algorithm        哈希算法
     * @return 哈希值（Base64编码）
     * @throws Exception 哈希计算异常
     */
    public static String hash(String data, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * HMAC计算（SHA-256）
     *
     * @param data             数据
     * @param secretKey        密钥
     * @return HMAC值（Base64编码）
     * @throws Exception HMAC计算异常
     */
    public static String hmacSHA256(String data, SecretKey secretKey) throws Exception {
        return hmac(data, secretKey, HMAC_SHA256);
    }

    /**
     * HMAC计算（SHA-512）
     *
     * @param data             数据
     * @param secretKey        密钥
     * @return HMAC值（Base64编码）
     * @throws Exception HMAC计算异常
     */
    public static String hmacSHA512(String data, SecretKey secretKey) throws Exception {
        return hmac(data, secretKey, HMAC_SHA512);
    }

    /**
     * 通用HMAC计算
     *
     * @param data             数据
     * @param secretKey        密钥
     * @param algorithm        HMAC算法
     * @return HMAC值（Base64编码）
     * @throws Exception HMAC计算异常
     */
    public static String hmac(String data, SecretKey secretKey, String algorithm) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKey);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /**
     * 生成随机密钥
     *
     * @param algorithm        算法
     * @param keySize          密钥长度（bits）
     * @return 密钥
     * @throws Exception 密钥生成异常
     */
    public static SecretKey generateSecretKey(String algorithm, int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * 生成RSA密钥对
     *
     * @param keySize          密钥长度（bits）
     * @return RSA密钥对
     * @throws Exception 密钥对生成异常
     */
    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 生成随机初始化向量（IV）
     *
     * @param size             IV大小（字节）
     * @return 随机IV
     */
    public static byte[] generateRandomIV(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * 从字节数组创建公钥
     *
     * @param publicKeyBytes   公钥字节数组
     * @param algorithm        算法
     * @return 公钥
     * @throws Exception 公钥创建异常
     */
    public static PublicKey createPublicKeyFromBytes(byte[] publicKeyBytes, String algorithm) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 从字节数组创建私钥
     *
     * @param privateKeyBytes  私钥字节数组
     * @param algorithm        算法
     * @return 私钥
     * @throws Exception 私钥创建异常
     */
    public static PrivateKey createPrivateKeyFromBytes(byte[] privateKeyBytes, String algorithm) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 从Base64编码字符串创建密钥
     *
     * @param base64Key        Base64编码的密钥
     * @param algorithm        算法
     * @return 密钥
     */
    public static SecretKey createSecretKeyFromBase64(String base64Key, String algorithm) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    /**
     * 将密钥转换为Base64编码字符串
     *
     * @param secretKey        密钥
     * @return Base64编码的密钥
     */
    public static String secretKeyToBase64(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * 将公钥转换为Base64编码字符串
     *
     * @param publicKey        公钥
     * @return Base64编码的公钥
     */
    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 将私钥转换为Base64编码字符串
     *
     * @param privateKey       私钥
     * @return Base64编码的私钥
     */
    public static String privateKeyToBase64(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * 生成随机盐值
     *
     * @param size             盐值大小（字节）
     * @return 随机盐值
     */
    public static byte[] generateSalt(int size) {
        byte[] salt = new byte[size];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static void validateKeySize( byte[] iv) {
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("IV must be 16 bytes for AES-CBC");
        }
    }

    public static void main(String[] args) {
        // 测试 ECB CBC 加密
        String originalText = "这是一段需要加密的敏感信息，包含中文字符和特殊符号!@#$%^&*()";
        System.out.println("原始数据: " + originalText);
        try {
            SecretKey secretKey = EncryptionService.generateSecretKey(AES_ALGORITHM, 128);
            byte[] iv = EncryptionService.generateRandomIV(16);

            {
                String ciphertext = EncryptionService.aesEncryptCBC(originalText, secretKey, iv);
                System.out.println("Original: " + originalText);
                System.out.println("cbc-Encrypted: " + ciphertext);

                String decrypted = EncryptionService.aesDecryptCBC(ciphertext, secretKey, iv);
                System.out.println("cbc-Decrypted: " + decrypted);
                System.out.println("Original     : " + originalText);
            }
            {
                String ciphertext = EncryptionService.aesEncryptECB(originalText, secretKey);
                System.out.println("Original: " + originalText);
                System.out.println("ECB-Encrypted: " + ciphertext);

                String decrypted = EncryptionService.aesDecryptECB(ciphertext, secretKey);
                System.out.println("ECB-Decrypted: " + decrypted);
                System.out.println("Original     : " + originalText);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }

    }
}
