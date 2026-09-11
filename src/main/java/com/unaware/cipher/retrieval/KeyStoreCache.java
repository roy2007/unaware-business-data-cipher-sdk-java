package com.unaware.cipher.retrieval;

import com.unaware.cipher.common.Constant;
import com.unaware.cipher.keystore.KeyStoreManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 密钥库缓存类，提供高效的密钥与证书检索功能
 *
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 */
public class KeyStoreCache {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreCache.class);

    private final KeyStoreManager keyStoreManager;
    private final ConcurrentHashMap<String, CachedKey> keyCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Certificate> certificateCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();
    private boolean cacheEnabled;

    /**
     * 构造函数
     *
     * @param keyStoreManager 密钥库管理器实例
     */
    public KeyStoreCache(KeyStoreManager keyStoreManager) {
        this.keyStoreManager = keyStoreManager;
        this.cacheEnabled = true;
    }

    /**
     * 存储第三方密钥到密钥库并缓存
     *
     * @param keyId       密钥ID
     * @param secretKey   密钥
     * @param keyPassword 密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeThirdPartyKey(String keyId, SecretKey secretKey, String keyPassword) throws KeyStoreException {
        if (keyCache.containsKey(keyId)) {
            throw new IllegalArgumentException("Third party key ID already exists in cache");
        }
        // 存储到密钥库
        keyStoreManager.storeThirdPartyKey(keyId, secretKey, keyPassword);

        // 更新缓存
        if (cacheEnabled) {
            keyCache.put(keyId, new CachedKey(secretKey, KeyType.SECRET_KEY, keyPassword));
        }
    }

    /**
     * 存储rootKey密钥到密钥库并缓存
     *
     * @param rootKeyId       密钥ID
     * @param rootKey         密钥
     * @param rootKeyPassword 密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeRootKey(String rootKeyId, SecretKey rootKey, String rootKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (keyCache.containsKey(rootKeyId)) {
            throw new IllegalArgumentException("Root key ID already exists in cache");
        }
        keyStoreManager.storeRootKey(rootKeyId, rootKey, rootKeyPassword);
        keyStoreManager.saveKeyStore();

        // 更新缓存
        if (cacheEnabled) {
            keyCache.put(rootKeyId, new CachedKey(rootKey, KeyType.SECRET_KEY, rootKeyPassword));
        }
    }

    public void deleteByKeyId(String rootKeyId, String rootKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, CertificateException {
        SecretKey secretKey = keyStoreManager.getRootKey(rootKeyPassword, rootKeyId);
        if (secretKey != null) {
            keyStoreManager.deleteEntry(rootKeyId);
            keyStoreManager.saveKeyStore();
        }

        // 更新缓存
        if (cacheEnabled) {
            keyCache.remove(rootKeyId);
        }
    }

    /**
     * 存储rootKey密钥到密钥库并缓存, 密钥ID默认使用"ROOT_KEY"
     *
     * @param rootKey         密钥
     * @param rootKeyPassword 密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeDefaultRootKey(SecretKey rootKey, String rootKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        String rootKeyId = Constant.ROOT_KEY_ID;
        if (keyCache.containsKey(rootKeyId)) {
            throw new IllegalArgumentException("Default root key ID already exists in cache");
        }
        storeRootKey(rootKeyId, rootKey, rootKeyPassword);
    }

    /**
     * 根据密钥ID获取第三方密钥
     *
     * @param keyId       密钥ID
     * @param keyPassword 密钥保护密码
     * @return 密钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public SecretKey getThirdPartyKey(String keyId, String keyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        SecretKey secretKey = null;
        if (cacheEnabled && keyCache.containsKey(keyId)) {
            CachedKey cachedKey = keyCache.get(keyId);
            if (cachedKey.getType() == KeyType.SECRET_KEY && cachedKey.getPassword().equals(keyPassword)) {
                secretKey = (SecretKey) cachedKey.getKey();
            }
        }
        if (secretKey != null) {
            logger.debug("从缓存中获取第三方密钥命中：{}", keyId);
            return secretKey;
        }

        // 从密钥库获取
        secretKey = keyStoreManager.getThirdPartyKey(keyId, keyPassword);
        // 缓存结果
        if (cacheEnabled && secretKey != null) {
            keyCache.put(keyId, new CachedKey(secretKey, KeyType.SECRET_KEY, keyPassword));
        }

        return secretKey;
    }

    public void deleteThirdPartyByKeyId(String keyId, String rootKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, CertificateException {
        SecretKey secretKey = keyStoreManager.getThirdPartyKey(keyId, rootKeyPassword);
        if (secretKey != null) {
            keyStoreManager.deleteEntry("THIRD_PARTY_" + keyId);
            keyStoreManager.saveKeyStore();
        }

        // 更新缓存
        if (cacheEnabled) {
            keyCache.remove(keyId);
        }
    }

    /**
     * 根据密钥ID获取第三方密钥
     *
     * @param rootKeyId       密钥ID
     * @param rootKeyPassword 密钥保护密码
     * @return 密钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public SecretKey getRootKey(String rootKeyId, String rootKeyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        SecretKey rootSecretKey = null;
        if (cacheEnabled && keyCache.containsKey(rootKeyId)) {
            CachedKey cachedKey = keyCache.get(rootKeyId);
            if (cachedKey.getType() == KeyType.SECRET_KEY && cachedKey.getPassword().equals(rootKeyPassword)) {
                rootSecretKey = (SecretKey) cachedKey.getKey();
            }
        }
        if (rootSecretKey != null) {
            logger.debug("从缓存中获取root密钥命中：{}", rootKeyId);
            return rootSecretKey;
        }

        // 从密钥库获取
        rootSecretKey = keyStoreManager.getRootKey(rootKeyPassword, rootKeyId);

        // 缓存结果
        if (cacheEnabled && rootSecretKey != null) {
            keyCache.put(rootKeyId, new CachedKey(rootSecretKey, KeyType.SECRET_KEY, rootKeyPassword));
        }
        return rootSecretKey;
    }

    /**
     * 存储RSA密钥对到密钥库并缓存
     *
     * @param keyId              密钥ID
     * @param keyPair            RSA密钥对
     * @param privateKeyPassword 私钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeRSAKeyPair(String keyId, KeyPair keyPair, String privateKeyPassword) throws KeyStoreException {
        if (keyCache.containsKey(keyId + ".private")) {
            throw new IllegalArgumentException("RSA key pair ID already exists in cache");
        }
        // 存储到密钥库
        keyStoreManager.storeRSAKeyPair(keyId, keyPair, privateKeyPassword);

        // 更新缓存
        if (cacheEnabled) {
            keyCache.put(keyId + ".private", new CachedKey(keyPair.getPrivate(), KeyType.PRIVATE_KEY, privateKeyPassword));
            publicKeyCache.put(keyId + ".public", keyPair.getPublic());
        }
    }

    /**
     * 根据密钥ID获取RSA私钥
     *
     * @param keyId              密钥ID
     * @param privateKeyPassword 私钥保护密码
     * @return RSA私钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public PrivateKey getRSAPrivateKey(String keyId, String privateKeyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        PrivateKey privateKey = null;
        String cacheKey = keyId + ".private";
        if (cacheEnabled && keyCache.containsKey(cacheKey)) {
            CachedKey cachedKey = keyCache.get(cacheKey);
            if (cachedKey.getType() == KeyType.PRIVATE_KEY && cachedKey.getPassword().equals(privateKeyPassword)) {
                privateKey = (PrivateKey) cachedKey.getKey();
            }
        }
        if (privateKey != null) {
            logger.debug("从缓存中获取RSA私钥命中：{}", keyId);
            return privateKey;
        }

        // 从密钥库获取
        privateKey = keyStoreManager.getRSAPrivateKey(keyId, privateKeyPassword);

        // 缓存结果
        if (cacheEnabled && privateKey != null) {
            keyCache.put(cacheKey, new CachedKey(privateKey, KeyType.PRIVATE_KEY, privateKeyPassword));
        }

        return privateKey;
    }

    /**
     * 根据密钥ID获取RSA公钥
     *
     * @param keyId 密钥ID
     * @return RSA公钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public PublicKey getRSAPublicKey(String keyId) throws KeyStoreException {
        PublicKey publicKey = null;
        String cacheKey = keyId + ".public";
        if (cacheEnabled && publicKeyCache.containsKey(cacheKey)) {
            publicKey = publicKeyCache.get(cacheKey);
        }
        if (publicKey != null) {
            logger.debug("从缓存中获取RSA公钥命中：{}", keyId);
            return publicKey;
        }

        // 从密钥库获取
        publicKey = keyStoreManager.getRSAPublicKey(keyId);

        // 缓存结果
        if (cacheEnabled && publicKey != null) {
            publicKeyCache.put(cacheKey, publicKey);
        }

        return publicKey;
    }

    /**
     * 存储证书到密钥库并缓存
     *
     * @param alias       证书别名
     * @param certificate 证书
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeCertificate(String alias, Certificate certificate) throws KeyStoreException {
        if (certificateCache.containsKey(alias)) {
            throw new IllegalArgumentException("Certificate alias already exists in cache");
        }
        // 存储到密钥库
        keyStoreManager.storeCertificate(alias, certificate);

        // 更新缓存
        if (cacheEnabled) {
            certificateCache.put(alias, certificate);
            // 同时缓存证书中的公钥
            publicKeyCache.put(alias + ".public", certificate.getPublicKey());
        }
    }

    /**
     * 根据别名获取证书
     *
     * @param alias 证书别名
     * @return 证书
     * @throws KeyStoreException 密钥库操作异常
     */
    public Certificate getCertificate(String alias) throws KeyStoreException {
        Certificate certificate = null;
        if (cacheEnabled && certificateCache.containsKey(alias)) {
            certificate = certificateCache.get(alias);
        }
        if (certificate != null) {
            logger.debug("从缓存中获取证书命中：{}", alias);
            return certificate;
        }

        // 从密钥库获取
        certificate = keyStoreManager.getCertificate(alias);

        // 缓存结果
        if (cacheEnabled && certificate != null) {
            certificateCache.put(alias, certificate);
            publicKeyCache.put(alias + ".public", certificate.getPublicKey());
        }

        return certificate;
    }

    /**
     * 根据证书别名获取公钥
     *
     * @param certificateAlias 证书别名
     * @return 公钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public PublicKey getPublicKeyFromCertificate(String certificateAlias) throws KeyStoreException {
        PublicKey publicKey = null;
        String cacheKey = certificateAlias + ".public";
        if (cacheEnabled && publicKeyCache.containsKey(cacheKey)) {
            publicKey = publicKeyCache.get(cacheKey);
        }
        if (publicKey != null) {
            logger.debug("从缓存中获取公钥命中：{}", certificateAlias);
            return publicKey;
        }

        // 从证书获取公钥
        Certificate certificate = getCertificate(certificateAlias);
        if (certificate == null) {
            return null;
        }

        publicKey = certificate.getPublicKey();

        // 缓存结果
        if (cacheEnabled) {
            publicKeyCache.put(cacheKey, publicKey);
        }

        return publicKey;
    }

    /**
     * 按密钥类型查询密钥
     *
     * @param keyType 密钥类型
     * @return 密钥映射表
     * @throws KeyStoreException 密钥库操作异常
     */
    public Map<String, Object> getKeysByType(KeyType keyType) throws KeyStoreException {
        Map<String, Object> result = new HashMap<>();

        // 先检查缓存
        if (cacheEnabled) {
            for (Map.Entry<String, CachedKey> entry : keyCache.entrySet()) {
                if (entry.getValue().getType() == keyType) {
                    result.put(entry.getKey(), entry.getValue().getKey());
                }
            }
        }

        // 从密钥库获取所有密钥（这部分需要在KeyStoreManager中实现完整的枚举功能）
        // TODO: 实现从密钥库枚举所有密钥的功能

        return result;
    }

    /**
     * 检查密钥是否存在
     *
     * @param keyId 密钥ID
     * @return 是否存在
     * @throws KeyStoreException 密钥库操作异常
     */
    public boolean containsKey(String keyId) throws KeyStoreException {
        if (cacheEnabled && (keyCache.containsKey(keyId) ||
                keyCache.containsKey(keyId + ".private") ||
                publicKeyCache.containsKey(keyId + ".public"))) {
            return true;
        }
        return keyStoreManager.containsAlias(keyId) ||
                keyStoreManager.containsAlias(keyId + ".private") ||
                keyStoreManager.containsAlias(keyId + ".public");
    }

    /**
     * 检查证书是否存在
     *
     * @param alias 证书别名
     * @return 是否存在
     * @throws KeyStoreException 密钥库操作异常
     */
    public boolean containsCertificate(String alias) throws KeyStoreException {
        if (cacheEnabled && certificateCache.containsKey(alias)) {
            return true;
        }
        return keyStoreManager.containsAlias(alias);
    }

    /**
     * 删除密钥并清除缓存
     *
     * @param keyId 密钥ID
     * @throws KeyStoreException 密钥库操作异常
     */
    public void deleteKey(String keyId) throws KeyStoreException {
        // 删除密钥库中的密钥
        keyStoreManager.deleteEntry(keyId);
        keyStoreManager.deleteEntry(keyId + ".private");
        keyStoreManager.deleteEntry(keyId + ".public");

        // 清除缓存
        keyCache.remove(keyId);
        keyCache.remove(keyId + ".private");
        publicKeyCache.remove(keyId + ".public");
    }

    /**
     * 删除证书并清除缓存
     *
     * @param alias 证书别名
     * @throws KeyStoreException 密钥库操作异常
     */
    public void deleteCertificate(String alias) throws KeyStoreException {
        // 删除密钥库中的证书
        keyStoreManager.deleteEntry(alias);

        // 清除缓存
        certificateCache.remove(alias);
        publicKeyCache.remove(alias + ".public");
    }

    /**
     * 保存密钥库更改
     *
     * @throws KeyStoreException        密钥库操作异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws CertificateException     证书处理异常
     * @throws java.io.IOException      IO操作异常
     */
    public void saveKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, java.io.IOException {
        keyStoreManager.saveKeyStore();
    }

    /**
     * 关闭密钥库缓存
     */
    public void close() {
        clearCache();
        keyStoreManager.close();
    }

    /**
     * 密钥类型枚举
     */
    public enum KeyType {
        SECRET_KEY,
        PUBLIC_KEY,
        PRIVATE_KEY,
        KEY_PAIR
    }

    /**
     * 启用缓存
     */
    public void enableCache() {
        this.cacheEnabled = true;
    }

    /**
     * 禁用缓存
     */
    public void disableCache() {
        this.cacheEnabled = false;
        clearCache();
    }

    /**
     * 清除所有缓存
     */
    public void clearCache() {
        keyCache.clear();
        certificateCache.clear();
        publicKeyCache.clear();
    }

    /**
     * 缓存的密钥内部类
     */
    private static class CachedKey {
        private final Object key;
        private final KeyType type;
        private final String password;

        public CachedKey(Object key, KeyType type, String password) {
            this.key = key;
            this.type = type;
            this.password = password;
        }

        public Object getKey() {
            return key;
        }

        public KeyType getType() {
            return type;
        }

        public String getPassword() {
            return password;
        }
    }
}