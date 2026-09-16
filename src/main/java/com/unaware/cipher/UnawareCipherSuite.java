package com.unaware.cipher;

import com.unaware.cipher.common.Constant;
import com.unaware.cipher.derivation.KeyDerivation;
import com.unaware.cipher.exception.EncryptionException;
import com.unaware.cipher.exception.ErrorCode;
import com.unaware.cipher.fpe.FPEEncryption;
import com.unaware.cipher.keystore.KeyStoreManager;
import com.unaware.cipher.retrieval.KeyStoreCache;
import com.unaware.cipher.service.EncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * UnawareCipherSuite加密SDK主入口类，提供统一的API访问点
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年05月02日
 */
public class UnawareCipherSuite {
    private static final Logger logger = LoggerFactory.getLogger(UnawareCipherSuite.class);

    private final KeyStoreManager keyStoreManager;
    private final KeyStoreCache keyStoreCache;
    private boolean initialized;
    private final static ConcurrentHashMap<String, KeyStoreManager> keyStoreManagerCache = new ConcurrentHashMap<>();

    // 支持的字符集常量
    public static final String DIGITS = "0123456789";
    private static final String UPPER_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String ALPHANUMERIC_UPPER = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String EMAIL = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-";
    public static final String ID_CARD = "0123456789X";
    public static final Pattern ID_CARD_18_PATTERN = Pattern.compile("^[0-9]{17}[0-9Xx]$");
    private static final String SUFFIX = "MjMhQCM=";

    /**
     * 私有构造函数
     *
     * @param keyStoreManager 密钥库管理器
     */
    private UnawareCipherSuite(KeyStoreManager keyStoreManager) {
        this.keyStoreManager = keyStoreManager;
        this.keyStoreCache = new KeyStoreCache(keyStoreManager);
        this.initialized = true;
    }

    // ==================== 密钥库管理 ====================
    /**
     * 创建新的SDK实例（创建新的密钥库）
     *
     * @param keyStorePath     密钥库文件路径
     * @param keyStorePassword 密钥库密码
     * @return SDK实例
     * @throws EncryptionException 加密异常
     */
    public static UnawareCipherSuite createNew(String keyStorePath, String keyStorePassword) throws EncryptionException {
        try {
            KeyStoreManager keyStoreManager = new KeyStoreManager(keyStorePath, keyStorePassword, true);
            cacheKeyStoreManager(keyStorePath, keyStoreManager);
            return new UnawareCipherSuite(keyStoreManager);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_CREATE_ERROR, "创建密钥库失败", e);
        }
    }

    /**
     * 加载现有SDK实例（使用现有密钥库）
     *
     * @param keyStorePath     密钥库文件路径
     * @param keyStorePassword 密钥库密码
     * @return SDK实例
     * @throws EncryptionException 加密异常
     */
    public static UnawareCipherSuite loadExisting(String keyStorePath, String keyStorePassword) throws EncryptionException {
        try {
            KeyStoreManager keyStoreManager = getKeyStoreManager(keyStorePath);
            if (keyStoreManager == null) {
                keyStoreManager = new KeyStoreManager(keyStorePath, keyStorePassword, false);
                cacheKeyStoreManager(keyStorePath, keyStoreManager);
            }
            return new UnawareCipherSuite(keyStoreManager);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_LOAD_ERROR, "加载密钥库失败", e);
        }
    }

    private static void cacheKeyStoreManager(String keyStorePath, KeyStoreManager keyStoreManager) {
        keyStoreManagerCache.put(keyStorePath, keyStoreManager);
    }

    private static KeyStoreManager getKeyStoreManager(String keyStorePath) {
        KeyStoreManager keyStoreManager = keyStoreManagerCache.get(keyStorePath);
        if (keyStoreManager != null) {
            System.out.println("从缓存中获取密钥库管理器命中：" + keyStorePath);
        }
        return keyStoreManager;
    }

    // ==================== 密钥库管理 ====================

    /**
     * 创建并存储根密钥
     *
     * @param rootKeyPassword 根密钥保护密码
     * @return 根密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey createRootKey(String rootKeyPassword) throws EncryptionException {
        try {
            if (rootKeyPassword == null || rootKeyPassword.isEmpty()) {
                throw new EncryptionException(ErrorCode.KEY_PASSWORD_ERROR, "根密钥存储密码不能为空");
            }
            // 生成随机种子
            byte[] seed = new byte[32];
            new SecureRandom().nextBytes(seed);

            // 创建根密钥
            SecretKey rootKey = KeyDerivation.createRootKey(seed);
            // 存储根密钥
            keyStoreCache.storeRootKey(Constant.ROOT_KEY_ID, rootKey, rootKeyPassword);
            keyStoreCache.saveKeyStore();
            return rootKey;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ROOT_KEY_CREATE_ERROR, "创建根密钥失败", e);
        }
    }

    /**
     * 创建并存储根密钥
     *
     * @param rootKeyId       根密钥标识
     * @param rootKeyStr      根密钥
     * @param rootKeyPassword 根密钥保护密码
     * @return 根密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey storeRootKey(String rootKeyId, String rootKeyStr, String rootKeyPassword) throws EncryptionException {
        try {
            if (rootKeyPassword == null || rootKeyPassword.isEmpty()) {
                throw new EncryptionException(ErrorCode.KEY_PASSWORD_ERROR, "根密钥存储密码不能为空");
            }
            // 根密钥采用base64方式承载可读的，所以需要再转成字节
            byte[] rootKeyBytes = Base64.getDecoder().decode(rootKeyStr);
            if (rootKeyBytes.length != 32) {
                throw new IllegalArgumentException("Invalid key length: expected 32 bytes for AES-256, got " + rootKeyBytes.length);
            }
            if (rootKeyId == null || rootKeyId.trim().isEmpty()) {
                rootKeyId = Constant.ROOT_KEY_ID;
            }

            // 存储根密钥
            SecretKey rootKey = new SecretKeySpec(rootKeyBytes, "AES");
            keyStoreCache.storeRootKey(rootKeyId, rootKey, rootKeyPassword);
            keyStoreCache.saveKeyStore();

            return rootKey;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ROOT_KEY_CREATE_ERROR, "创建根密钥失败", e);
        }
    }

    /**
     * 从密钥库中删除指定别名的密钥
     *
     * @param keyId       密钥标识
     * @param keyPassword 密钥密码（也用作条目密码）
     * @throws Exception 删除失败时抛出异常
     */
    public void deleteByKeyId(String keyId, String keyPassword) throws Exception {
        keyStoreCache.deleteByKeyId(keyId, keyPassword);
    }

    /**
     * 获取根密钥
     *
     * @param rootKeyPassword 根密钥保护密码
     * @return 根密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey getDefaultRootKey(String rootKeyPassword) throws EncryptionException {
        if (rootKeyPassword == null || rootKeyPassword.isEmpty()) {
            throw new EncryptionException(ErrorCode.KEY_PASSWORD_ERROR, "根密钥存储密码不能为空");
        }
        return getRootKey(rootKeyPassword, Constant.ROOT_KEY_ID);
    }

    /**
     * 获取根密钥
     *
     * @param rootKeyPassword 根密钥保护密码
     * @param rootKeyId       根密钥标识
     * @return 根密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey getRootKey(String rootKeyPassword, String rootKeyId) throws EncryptionException {
        try {
            if (rootKeyPassword == null || rootKeyPassword.isEmpty()) {
                throw new EncryptionException(ErrorCode.KEY_PASSWORD_ERROR, "根密钥存储密码不能为空");
            }
            if (rootKeyId == null || rootKeyId.trim().isEmpty()) {
                rootKeyId = Constant.ROOT_KEY_ID;
            }
            SecretKey rootKey = keyStoreCache.getRootKey(rootKeyId, rootKeyPassword);
            if (rootKey == null) {
                throw new EncryptionException(ErrorCode.ROOT_KEY_NOT_FOUND, "根密钥未找到");
            }
            return rootKey;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ROOT_KEY_NOT_FOUND, "获取根密钥失败", e);
        }
    }

    /**
     * 从密钥派生业务模块专用密钥
     *
     * @param rootKey          根密钥
     * @param subjectDomain    主题域（业务模块标识）
     * @param keyVersion       密钥版本
     * @return 派生的密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey deriveKey(SecretKey rootKey, String subjectDomain, int keyVersion) throws EncryptionException {
        try {
            return KeyDerivation.deriveKey(rootKey, subjectDomain, keyVersion);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_DERIVATION_ERROR, "派生密钥失败", e);
        }
    }

    /**
     * 从根密钥派生业务模块专用密钥
     *
     * @param rootKeyId          根密钥
     * @param rootKeyPassword 根密钥保护密码
     * @param subjectDomain    主题域（业务模块标识）
     * @param keyVersion       密钥版本
     * @return 派生的密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey deriveKeyByRootKey(String rootKeyId, String rootKeyPassword, String subjectDomain, int keyVersion) throws EncryptionException {
        try {
            if (rootKeyPassword == null || rootKeyPassword.isEmpty()) {
                throw new EncryptionException(ErrorCode.KEY_PASSWORD_ERROR, "根密钥存储密码不能为空");
            }
            SecretKey rootKey = keyStoreManager.getRootKey(rootKeyPassword, rootKeyId);
            if (rootKey == null) {
                throw new EncryptionException(ErrorCode.ROOT_KEY_NOT_FOUND, "根密钥未找到");
            }
            return deriveKey(rootKey, subjectDomain, keyVersion);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_DERIVATION_ERROR, "派生密钥失败", e);
        }
    }

    // ==================== 密钥与证书管理 ====================
    /**
     * 存储第三方密钥
     *
     * @param keyId            密钥ID
     * @param secretKey        密钥
     * @param keyPassword      密钥保护密码
     * @throws EncryptionException 加密异常
     */
    public void storeThirdPartyKey(String keyId, SecretKey secretKey, String keyPassword) throws EncryptionException {
        try {
            keyStoreCache.storeThirdPartyKey(keyId, secretKey, keyPassword);
            keyStoreCache.saveKeyStore();
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_SAVE_ERROR, "存储第三方密钥失败", e);
        }
    }

    /**
     * 获取第三方密钥
     *
     * @param keyId            密钥ID
     * @param keyPassword      密钥保护密码
     * @return 密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey getThirdPartyKey(String keyId, String keyPassword) throws EncryptionException {
        try {
            SecretKey secretKey = keyStoreCache.getThirdPartyKey(keyId, keyPassword);
            if (secretKey == null) {
                throw new EncryptionException(ErrorCode.KEY_STORE_ENTRY_NOT_FOUND, "第三方密钥未找到");
            }
            return secretKey;
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_ENTRY_NOT_FOUND, "获取第三方密钥失败", e);
        }
    }

    /**
     * 删除第三方密钥
     *
     * @param keyId            密钥ID
     * @param keyPassword      密钥保护密码
     * @throws EncryptionException 加密异常
     */
    public void deleteThirdPartyByKeyId(String keyId, String keyPassword) throws EncryptionException {
        try {
            keyStoreCache.deleteThirdPartyByKeyId(keyId, keyPassword);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_SAVE_ERROR, "删除第三方密钥失败", e);
        }
    }

    /**
     * 存储证书
     *
     * @param alias            证书别名
     * @param certificate      证书
     * @throws EncryptionException 加密异常
     */
    public void storeCertificate(String alias, Certificate certificate) throws EncryptionException {
        try {
            keyStoreCache.storeCertificate(alias, certificate);
            keyStoreCache.saveKeyStore();
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_SAVE_ERROR, "存储证书失败", e);
        }
    }

    /**
     * 获取证书
     *
     * @param alias            证书别名
     * @return 证书
     * @throws EncryptionException 加密异常
     */
    public Certificate getCertificate(String alias) throws EncryptionException {
        try {
            Certificate certificate = keyStoreCache.getCertificate(alias);
            if (certificate == null) {
                throw new EncryptionException(ErrorCode.KEY_STORE_ENTRY_NOT_FOUND, "证书未找到");
            }
            return certificate;
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_ENTRY_NOT_FOUND, "获取证书失败", e);
        }
    }

    // ==================== AES加密算法 ====================
    /**
     * AES加密（CBC模式）
     *
     * @param plaintext        明文
     * @param secretKey        密钥
     * @param iv               初始化向量
     * @return 加密后的密文（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String aesEncryptCBC(String plaintext, SecretKey secretKey, byte[] iv) throws EncryptionException {
        try {
            return EncryptionService.aesEncryptCBC(plaintext, secretKey, iv);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ENCRYPTION_ERROR, "AES加密失败", e);
        }
    }

    /**
     * AES解密（CBC模式）
     *
     * @param ciphertext       密文（Base64编码）
     * @param secretKey        密钥
     * @param iv               初始化向量
     * @return 解密后的明文
     * @throws EncryptionException 加密异常
     */
    public String aesDecryptCBC(String ciphertext, SecretKey secretKey, byte[] iv) throws EncryptionException {
        try {
            return EncryptionService.aesDecryptCBC(ciphertext, secretKey, iv);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.DECRYPTION_ERROR, "AES解密失败", e);
        }
    }

    /**
     * AES加密（ECB模式）
     *
     * @param plaintext        明文
     * @param secretKey        密钥
     * @return 加密后的密文（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String aesEncryptECB(String plaintext, SecretKey secretKey) throws EncryptionException {
        try {
            return EncryptionService.aesEncryptECB(plaintext, secretKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ENCRYPTION_ERROR, "AES加密失败", e);
        }
    }

    /**
     * AES解密（ECB模式）
     *
     * @param ciphertext       密文（Base64编码）
     * @param secretKey        密钥
     * @return 解密后的明文
     * @throws EncryptionException 加密异常
     */
    public String aesDecryptECB(String ciphertext, SecretKey secretKey) throws EncryptionException {
        try {
            return EncryptionService.aesDecryptECB(ciphertext, secretKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.DECRYPTION_ERROR, "AES解密失败", e);
        }
    }

    /**
     * RSA加密
     *
     * @param plaintext        明文
     * @param publicKey        公钥
     * @return 加密后的密文（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String rsaEncrypt(String plaintext, PublicKey publicKey) throws EncryptionException {
        try {
            return EncryptionService.rsaEncrypt(plaintext, publicKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.ENCRYPTION_ERROR, "RSA加密失败", e);
        }
    }

    // ==================== RSA加密算法 ====================
    /**
     * RSA解密
     *
     * @param ciphertext       密文（Base64编码）
     * @param privateKey       私钥
     * @return 解密后的明文
     * @throws EncryptionException 加密异常
     */
    public String rsaDecrypt(String ciphertext, PrivateKey privateKey) throws EncryptionException {
        try {
            return EncryptionService.rsaDecrypt(ciphertext, privateKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.DECRYPTION_ERROR, "RSA解密失败", e);
        }
    }

    /**
     * RSA数字签名生成
     *
     * @param data             数据
     * @param privateKey       私钥
     * @param signatureAlgorithm 签名算法
     * @return 签名（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String rsaSign(String data, PrivateKey privateKey, String signatureAlgorithm) throws EncryptionException {
        try {
            return EncryptionService.rsaSign(data, privateKey, signatureAlgorithm);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.RSA_SIGN_ERROR, "RSA签名生成失败", e);
        }
    }

    /**
     * RSA数字签名验证
     *
     * @param data             数据
     * @param signature        签名（Base64编码）
     * @param publicKey        公钥
     * @param signatureAlgorithm 签名算法
     * @return 验证结果
     * @throws EncryptionException 加密异常
     */
    public boolean rsaVerify(String data, String signature, PublicKey publicKey, String signatureAlgorithm) throws EncryptionException {
        try {
            return EncryptionService.rsaVerify(data, signature, publicKey, signatureAlgorithm);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.RSA_VERIFY_ERROR, "RSA签名验证失败", e);
        }
    }

    /**
     * 哈希计算（SHA-256）
     *
     * @param data             数据
     * @return 哈希值（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String hashSHA256(String data) throws EncryptionException {
        try {
            return EncryptionService.hashSHA256(data);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.HASH_ERROR, "SHA-256哈希计算失败", e);
        }
    }

    /**
     * 哈希计算（SHA-512）
     *
     * @param data             数据
     * @return 哈希值（Base64编码）
     * @throws EncryptionException 加密异常
     */
    public String hashSHA512(String data) throws EncryptionException {
        try {
            return EncryptionService.hashSHA512(data);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.HASH_ERROR, "SHA-512哈希计算失败", e);
        }
    }

    // ==================== FPE加密 ====================
    /**
     * FPE加密（数字和字母混合）：数字→数字，字母→字母（保持大小写），其他不变
     *
     * @param input       输入字符串（数字和字母混合）
     * @param tweak       加密参数（16字节）
     * @param secretKey    密钥 (解密与加密密钥一致）
     * @return 加密后的字符串
     * @throws EncryptionException 加密异常
     */
    public String fpeEncrypt(String input, byte[] tweak, SecretKey secretKey) {
        if (input == null) {
            return null;
        }

        try {
            StringBuilder result = new StringBuilder();
            StringBuilder digitBuf = new StringBuilder();
            StringBuilder letterBuf = new StringBuilder();
            boolean[] isUpper = new boolean[input.length()];

            // 第一遍：收集数字和字母（转大写）
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                if (c >= '0' && c <= '9') {
                    digitBuf.append(c);
                } else if (c >= 'A' && c <= 'Z') {
                    letterBuf.append(c);
                    isUpper[i] = true;
                } else if (c >= 'a' && c <= 'z') {
                    letterBuf.append((char) (c - 32));
                    isUpper[i] = false;
                }
            }

            byte[] paddedKey = padOrTruncateTo16(secretKey.getEncoded());
            // 加密数字串（如果存在）
            String encDigits = "";
            if (digitBuf.length() > 0) {
                FPEEncryption fpe = new FPEEncryption(paddedKey, DIGITS);
                encDigits = fpe.encrypt(digitBuf.toString(), tweak);
            }

            // 加密字母串（如果存在）
            String encLetters = "";
            if (letterBuf.length() > 0) {
                FPEEncryption fpe = new FPEEncryption(paddedKey, UPPER_LETTERS);
                encLetters = fpe.encrypt(letterBuf.toString(), tweak);
            }

            // 第二遍：重建结果
            int dIdx = 0, lIdx = 0;
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                if (c >= '0' && c <= '9') {
                    result.append(encDigits.charAt(dIdx++));
                } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                    char encryptedUpper = encLetters.charAt(lIdx++);
                    result.append(isUpper[i] ? encryptedUpper : Character.toLowerCase(encryptedUpper));
                } else {
                    result.append(c);
                }
            }

            return result.toString();
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE加密失败", e);
        }
    }

    /**
     * FPE（使用默认字符集）
     *
     * @param phone 明文
     * @param tweak     调整值如 "138001009".getBytes()
     * @param secretKey 密钥
     * @return 密文
     * @throws EncryptionException 加密异常
     */
    public String fpeEncryptPhone(String phone, byte[] tweak, SecretKey secretKey) {
        return fpeEncrypt(phone, tweak, secretKey);
    }

    /**
     * FPE证件号（注意：如果识别身份证号：X 必须大写）,如果前端传值tweak，需要存储到库表中。否则无法解密密文为原值
     *
     * @param idCard 明文（注意：X 必须大写）
     * @param tweak  调整值如 "123456789".getBytes()
     * @param secretKey 密钥
     * @return 密文
     * @throws EncryptionException 加密异常
     */
    public String fpeEncryptIdCard(String idCard, byte[] tweak, SecretKey secretKey) {
        try {
            FPEEncryption fpe = null;
            String normalized = idCard.toUpperCase();
            if (ID_CARD_18_PATTERN.matcher(idCard).matches()) {
                fpe = new FPEEncryption(null, ID_CARD);
            } else {
                fpe = new FPEEncryption(null, ALPHANUMERIC_UPPER);
            }
            return fpeEncrypt(normalized, tweak, secretKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE证件加密失败", e);
        }
    }

    /**
     * FPE邮箱 local-part 加密（保留 @domain）
     *
     * @param email 明文（邮箱格式）
     * @param tweak 调整值
     * @param secretKey 密钥
     * @return 密文
     * @throws EncryptionException 加密异常
     */
    public String fpeEncryptEmailLocal(String email, byte[] tweak, SecretKey secretKey) {
        try {
            int atPos = email.lastIndexOf('@');
            if (atPos <= 0) {
                throw new IllegalArgumentException("Invalid email format");
            }
            String local = email.substring(0, atPos);
            String domain = email.substring(atPos);

            FPEEncryption fpe = new FPEEncryption(null, EMAIL);
            String encryptedLocal = fpeEncrypt(local, tweak, secretKey);
            return encryptedLocal + domain;
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE证件加密失败", e);
        }
    }

    /**
     * FPE（使用自定义字符集）
     *
     * @param plaintext 明文
     * @param charset   字符集
     * @param tweak     调整值
     * @param secretKey 密钥
     * @return 密文
     * @throws EncryptionException 加密异常
     */
    public String fpeEncrypt(String plaintext, String charset, byte[] tweak, SecretKey secretKey) throws EncryptionException {
        try {
            FPEEncryption fpe = new FPEEncryption(null, charset);
            return fpeEncrypt(plaintext, tweak, secretKey);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE加密失败", e);
        }
    }

    /**
     * FPE解密
     *
     * @param ciphertext 密文
     * @param tweak      调整值必须与加密时使用的调整值一致
     * @param secretKey 密钥必须与加密时使用的密钥一致
     * @return 明文
     * @throws EncryptionException 解密异常
     */
    public String fpeDecrypt(String ciphertext, byte[] tweak, SecretKey secretKey) throws EncryptionException {
        try {
            if (ciphertext == null) {
                return null;
            }

            try {
                StringBuilder result = new StringBuilder();
                StringBuilder digitBuf = new StringBuilder();
                StringBuilder letterBuf = new StringBuilder();
                boolean[] isUpper = new boolean[ciphertext.length()];

                // 第一遍：收集数字和字母（转大写）
                for (int i = 0; i < ciphertext.length(); i++) {
                    char c = ciphertext.charAt(i);
                    if (c >= '0' && c <= '9') {
                        digitBuf.append(c);
                    } else if (c >= 'A' && c <= 'Z') {
                        letterBuf.append(c);
                        isUpper[i] = true;
                    } else if (c >= 'a' && c <= 'z') {
                        letterBuf.append((char) (c - 32));
                        isUpper[i] = false;
                    }
                }

                byte[] paddedKey = padOrTruncateTo16(secretKey.getEncoded());
                // 加密数字串（如果存在）
                String encDigits = "";
                if (digitBuf.length() > 0) {
                    FPEEncryption fpe = new FPEEncryption(paddedKey, DIGITS);
                    encDigits = fpe.decrypt(digitBuf.toString(), tweak);
                }

                // 加密字母串（如果存在）
                String encLetters = "";
                if (letterBuf.length() > 0) {
                    FPEEncryption fpe = new FPEEncryption(paddedKey, UPPER_LETTERS);
                    encLetters = fpe.decrypt(letterBuf.toString(), tweak);
                }

                // 第二遍：重建结果
                int dIdx = 0, lIdx = 0;
                for (int i = 0; i < ciphertext.length(); i++) {
                    char c = ciphertext.charAt(i);
                    if (c >= '0' && c <= '9') {
                        result.append(encDigits.charAt(dIdx++));
                    } else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                        char encryptedUpper = encLetters.charAt(lIdx++);
                        result.append(isUpper[i] ? encryptedUpper : Character.toLowerCase(encryptedUpper));
                    } else {
                        result.append(c);
                    }
                }
                return result.toString();
            } catch (Exception e) {
                throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE解密失败", e);
            }
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.FPE_ENCRYPTION_ERROR, "FPE解密失败", e);
        }
    }
    // ==================== 辅助功能 ====================
    /**
     * 生成随机密钥
     *
     * @param algorithm        算法
     * @param keySize          密钥长度（bits）
     * @return 密钥
     * @throws EncryptionException 加密异常
     */
    public SecretKey generateSecretKey(String algorithm, int keySize) throws EncryptionException {
        try {
            return EncryptionService.generateSecretKey(algorithm, keySize);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_GENERATION_ERROR, "密钥生成失败", e);
        }
    }

    /**
     * 生成RSA密钥对
     *
     * @param keySize          密钥长度（bits）
     * @return RSA密钥对
     * @throws EncryptionException 加密异常
     */
    public KeyPair generateRSAKeyPair(int keySize) throws EncryptionException {
        try {
            return EncryptionService.generateRSAKeyPair(keySize);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.RSA_KEY_PAIR_GENERATION_ERROR, "RSA密钥对生成失败", e);
        }
    }

    /**
     * 生成随机初始化向量（IV）
     *
     * @param size             IV大小（字节）
     * @return 随机IV
     */
    public byte[] generateRandomIV(int size) {
        return EncryptionService.generateRandomIV(size);
    }

    /**
     * 生成随机tweak
     *
     * @return 随机tweak
     */
    public byte[] generateRandomTweak() {
        FPEEncryption fpe = new FPEEncryption(null);
        return fpe.generateRandomTweak();
    }

    /**
     * 对字节数组进行填充或截断，确保长度为16字节
     *
     * @param input 输入字节数组
     * @return 填充或截断后的16字节数组
     */
    public static byte[] padOrTruncateTo16(byte[] input) {
        if (input == null) {
            input = new byte[0];
        }
        byte[] result = new byte[16];
        int copyLen = Math.min(input.length, 16);
        System.arraycopy(input, 0, result, 0, copyLen);
        return result;
    }

    /**
     * 保存密钥库更改
     *
     * @throws EncryptionException 加密异常
     */
    public void saveKeyStore() throws EncryptionException {
        try {
            keyStoreCache.saveKeyStore();
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.KEY_STORE_SAVE_ERROR, "保存密钥库失败", e);
        }
    }

    /**
     * 启用缓存
     */
    public void enableCache() {
        keyStoreCache.enableCache();
    }

    /**
     * 禁用缓存
     */
    public void disableCache() {
        keyStoreCache.disableCache();
    }

    /**
     * 清除缓存
     */
    public void clearCache() {
        keyStoreManagerCache.clear();
        keyStoreCache.clearCache();
    }

    /**
     * 关闭SDK
     */
    public void close() {
        if (initialized) {
            keyStoreCache.close();
            keyStoreManagerCache.clear();
            initialized = false;
        }
    }

    /**
     * 检查SDK是否已初始化
     *
     * @return 是否已初始化
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * 获取版本信息
     *
     * @return 版本信息
     */
    public static String getVersion() {
        return "0.0.1-SNAPSHOT";
    }

    /**
     * 获取SDK名称
     *
     * @return SDK名称
     */
    public static String getName() {
        return "yunwuye Encryption cipherSuite for Java";
    }

    /**
     * 将Base64编码的字符串转换为密钥
     *
     * @param secretKeyStr Base64编码的密钥字符串
     * @param algorithm    算法
     * @return 密钥
     * @throws EncryptionException 加密异常
     */
    public static SecretKey getSecretKeyFromStr(String secretKeyStr, String algorithm) throws EncryptionException {
        try {
            // 检查密钥字符串是否为空，且密钥字符串一定是之前通过getSecretKeyStr方法转换为Base64编码的字符串
            if (secretKeyStr == null || secretKeyStr.isEmpty()) {
                throw new EncryptionException(ErrorCode.INVALID_SECRET_KEY_STRING, "密钥字符串不能为空");
            }
            byte[] decodedKey = Base64.getDecoder().decode(secretKeyStr);
            return new SecretKeySpec(decodedKey, algorithm);
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.SECRET_KEY_FROM_STRING_ERROR, "字符串转换为密钥失败", e);
        }
    }

    /**
     * 将密钥转换为Base64编码的字符串
     *
     * @param secretKey 密钥
     * @return Base64编码的密钥字符串
     * @throws EncryptionException 加密异常
     */
    public static String getSecretKeyStr(SecretKey secretKey) throws EncryptionException {
        try {
            //密钥因为是二进制数据，所以需要转换为Base64编码的字符串，才能在文本中传输
            if (secretKey == null) {
                throw new EncryptionException(ErrorCode.INVALID_SECRET_KEY_STRING, "密钥不能为空");
            }
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new EncryptionException(ErrorCode.SECRET_KEY_TO_STRING_ERROR, "密钥转换为字符串失败", e);
        }
    }

    /**
     * 常规密码字符串转Base64编码
     * @param password 常规密码字符串
     * @return 常规Base64编码的密码字符串
     */
    public static String getBase64Str(String password) {
        return Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));
    }

     /**
     * 常规Base64密码的解码操作
     * @param base64Password 常规Base64编码的密码字符串
     * @return 解码后的密码字符串
     */
    public static String getPasswordFromBase64(String base64Password) {
        return new String(Base64.getDecoder().decode(base64Password), StandardCharsets.UTF_8);
    }

     /**
     * 检查密钥库是否包含指定根密钥
     * @param rootKeyId 根密钥ID, 如果为空, 则默认使用"ROOT_KEY"
     * @return 是否包含指定根密钥
     */
    public boolean containsRootKey(String rootKeyId) {
        try {
            if(rootKeyId == null || rootKeyId.isEmpty()){
                rootKeyId = Constant.ROOT_KEY_ID;
            }
            return keyStoreCache.containsKey(rootKeyId);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

}
