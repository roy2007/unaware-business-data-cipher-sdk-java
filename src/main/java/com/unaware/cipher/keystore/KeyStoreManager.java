package com.unaware.cipher.keystore;

import com.unaware.cipher.common.Constant;

import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;
import java.io.*;

import com.unaware.cipher.exception.EncryptionException;
import com.unaware.cipher.exception.ErrorCode;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;

import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;


/**
 * JCEKS密钥库管理器类，负责密钥库的创建、加载与维护
 *
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 */
public class KeyStoreManager {

    private static final String KEY_STORE_TYPE = "JCEKS";
    private static final String SMB_PREFIX = "smb://";
    private KeyStore keyStore;
    private final char[] keyStorePassword;
    private final String keyStorePath;
    private final boolean isSmbPath;


    /**
     * 构造函数，用于创建新的密钥库或加载现有密钥库
     *
     * @param keyStorePath     密钥库文件路径
     * @param keyStorePassword 密钥库密码
     * @param createNew        是否创建新密钥库
     * @throws KeyStoreException        密钥库操作异常
     * @throws IOException              IO操作异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     * @throws CertificateException     证书处理异常
     */
    public KeyStoreManager(String keyStorePath, String keyStorePassword, boolean createNew) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, java.security.cert.CertificateException {
        if (keyStorePath == null || keyStorePath.trim().isEmpty()) {
            throw new IllegalArgumentException("KeyStore path cannot be null or empty");
        }
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            throw new EncryptionException(ErrorCode.KEY_STORE_PASSWORD_ERROR, "密钥库读写密码不能为空");
        }
        this.keyStorePath = keyStorePath.trim();
        this.isSmbPath = this.keyStorePath.startsWith(SMB_PREFIX);
        this.keyStorePassword = keyStorePassword.toCharArray();
        this.keyStore = KeyStore.getInstance(KEY_STORE_TYPE);

        if (createNew) {
            // 创建新的密钥库
            keyStore.load(null, this.keyStorePassword);
            saveKeyStore();
            return;
        }
        // 加载现有密钥库
        byte[] keystoreBytes = loadKeyStoreBytes();
        if (keystoreBytes == null || keystoreBytes.length == 0) {
            throw new IOException("Failed to load keystore from: " + keyStorePath);
        }
        try (ByteArrayInputStream bis = new ByteArrayInputStream(keystoreBytes)) {
            keyStore.load(bis, this.keyStorePassword);
        }
    }

    /**
     * 加载密钥库字节数组
     *
     * @return 密钥库字节数组
     */
    private byte[] loadKeyStoreBytes() throws IOException {
        if (isSmbPath) {
            SmbFile smbFile = new SmbFile(keyStorePath);
            if (!smbFile.exists()) {
                throw new FileNotFoundException("SMB keystore file not found: " + keyStorePath);
            }
            byte[] buffer = new byte[(int) smbFile.length()];
            try (InputStream in = smbFile.getInputStream()) {
                int total = 0, n;
                while ((n = in.read(buffer, total, buffer.length - total)) != -1) {
                    total += n;
                    if (total >= buffer.length) break;
                }
                return Arrays.copyOf(buffer, total);
            }

        } else {
            File localFile = new File(keyStorePath);
            if (!localFile.exists()) {
                throw new FileNotFoundException("Local keystore file not found: " + keyStorePath);
            }
            return Files.readAllBytes(localFile.toPath());
        }
    }

    /**
     * 保存密钥库到文件
     *
     * @throws KeyStoreException        密钥库操作异常
     * @throws IOException              IO操作异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public void saveKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, java.security.cert.CertificateException {
        try (ByteArrayOutputStream bass = new ByteArrayOutputStream()) {
            keyStore.store(bass, keyStorePassword);
            byte[] data = bass.toByteArray();

            if (isSmbPath) {
                SmbFile smbFile = new SmbFile(keyStorePath);
                SmbFile remoteFolder = new SmbFile(smbFile.getParent());
                if (!remoteFolder.exists()) {
                    remoteFolder.mkdirs();
                }
                try (SmbFileOutputStream out = new SmbFileOutputStream(smbFile)) {
                    out.write(data);
                }
            } else {
                File localFile = new File(keyStorePath);
                File parentDir = localFile.getParentFile();
                if (parentDir != null && !parentDir.exists() && !parentDir.mkdirs()) {
                    throw new RuntimeException("无法创建目录: " + parentDir.getAbsolutePath());
                }
                Files.write(localFile.toPath(), data);
            }
        }
    }

    /**
     * 存储根密钥到密钥库
     *
     * @param rootKey         根密钥
     * @param rootKeyPassword 根密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeRootKey(SecretKey rootKey, String rootKeyPassword) throws KeyStoreException {
        if (keyStore.containsAlias(Constant.ROOT_KEY_ID)) {
            throw new IllegalArgumentException("ROOT_KEY already exists in the key store");
        }
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(rootKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(rootKeyPassword.toCharArray());
        keyStore.setEntry(Constant.ROOT_KEY_ID, secretKeyEntry, protectionParameter);
    }

    /**
     * 存储根密钥到密钥库
     *
     * @param rootKeyId       根密钥标识
     * @param rootKey         根密钥
     * @param rootKeyPassword 根密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeRootKey(String rootKeyId, SecretKey rootKey, String rootKeyPassword) throws KeyStoreException {
        if (keyStore.containsAlias(rootKeyId)) {
            throw new IllegalArgumentException(String.format("ROOT_KEY:%s already exists in the key store", rootKeyId));
        }
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(rootKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(rootKeyPassword.toCharArray());
        keyStore.setEntry(rootKeyId, secretKeyEntry, protectionParameter);
    }

    /**
     * 获取根密钥
     *
     * @param rootKeyPassword 根密钥保护密码
     * @return 根密钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public SecretKey getRootKey(String rootKeyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        return getRootKey(rootKeyPassword, null);
    }

    /**
     * 获取根密钥
     *
     * @param rootKeyPassword 根密钥保护密码
     * @param rootKeyId       根密钥标识
     * @return 根密钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public SecretKey getRootKey(String rootKeyPassword, String rootKeyId) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (null == rootKeyId || rootKeyId.isEmpty()) {
            rootKeyId = Constant.ROOT_KEY_ID;
        }
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(rootKeyPassword.toCharArray());
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(rootKeyId, protectionParameter);
        return entry != null ? entry.getSecretKey() : null;
    }

    /**
     * 存储第三方密钥到密钥库
     *
     * @param keyId       密钥ID
     * @param secretKey   密钥
     * @param keyPassword 密钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeThirdPartyKey(String keyId, SecretKey secretKey, String keyPassword) throws KeyStoreException {
        if (keyStore.containsAlias("THIRD_PARTY_" + keyId)) {
            throw new IllegalArgumentException(String.format("THIRD_PARTY_KEY:%s already exists in the key store", keyId));
        }
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(keyPassword.toCharArray());
        keyStore.setEntry("THIRD_PARTY_" + keyId, secretKeyEntry, protectionParameter);
    }

    /**
     * 删除第三方密钥
     *
     * @param keyId 密钥ID
     * @throws KeyStoreException 密钥库操作异常
     */
    public void deleteThirdPartyByKeyId(String keyId) throws KeyStoreException {
        keyStore.deleteEntry("THIRD_PARTY_" + keyId);
    }

    /**
     * 获取第三方密钥
     *
     * @param keyId       密钥ID
     * @param keyPassword 密钥保护密码
     * @return 密钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public SecretKey getThirdPartyKey(String keyId, String keyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(keyPassword.toCharArray());
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry("THIRD_PARTY_" + keyId, protectionParameter);
        return entry != null ? entry.getSecretKey() : null;
    }

    /**
     * 存储证书到密钥库
     *
     * @param alias       证书别名
     * @param certificate 证书
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeCertificate(String alias, Certificate certificate) throws KeyStoreException {
        if (keyStore.containsAlias(alias)) {
            throw new IllegalArgumentException(String.format("CERTIFICATE: %s already exists in the key store", alias));
        }
        keyStore.setCertificateEntry(alias, certificate);
    }

    /**
     * 获取证书
     *
     * @param alias 证书别名
     * @return 证书
     * @throws KeyStoreException 密钥库操作异常
     */
    public Certificate getCertificate(String alias) throws KeyStoreException {
        return keyStore.getCertificate(alias);
    }

    /**
     * 获取密钥库中的所有别名
     *
     * @return 别名枚举
     * @throws KeyStoreException 密钥库操作异常
     */
    public Enumeration<String> getAliases() throws KeyStoreException {
        return keyStore.aliases();
    }

    /**
     * 检查密钥库中是否存在指定别名
     *
     * @param alias 别名
     * @return 是否存在
     * @throws KeyStoreException 密钥库操作异常
     */
    public boolean containsAlias(String alias) throws KeyStoreException {
        return keyStore.containsAlias(alias);
    }

    /**
     * 存储RSA密钥对到密钥库
     *
     * @param keyId              密钥ID,或应用系统标识AccessKeyId
     * @param keyPair            RSA密钥对
     * @param privateKeyPassword 私钥保护密码
     * @throws KeyStoreException 密钥库操作异常
     */
    public void storeRSAKeyPair(String keyId, java.security.KeyPair keyPair, String privateKeyPassword) throws KeyStoreException {
        // 存储公钥
        if (keyStore.containsAlias(keyId + ".public")) {
            throw new IllegalArgumentException(String.format("RSA_PUBLIC_KEY: %s already exists in the key store", keyId));
        }
        KeyStore.SecretKeyEntry publicKeyEntry = new KeyStore.SecretKeyEntry(new javax.crypto.spec.SecretKeySpec(keyPair.getPublic().getEncoded(), "RSA"));
        keyStore.setEntry(keyId + ".public", publicKeyEntry, new KeyStore.PasswordProtection(this.keyStorePassword));
    }

    /**
     * 获取RSA私钥
     *
     * @param keyId              密钥ID,或应用系统标识AccessKeyId
     * @param privateKeyPassword 私钥保护密码
     * @return RSA私钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public java.security.PrivateKey getRSAPrivateKey(String keyId, String privateKeyPassword) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(privateKeyPassword.toCharArray());
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyId + ".private", protectionParameter);
        return entry != null ? entry.getPrivateKey() : null;
    }

    /**
     * 获取RSA公钥
     *
     * @param keyId 密钥ID,或应用系统标识AccessKeyId
     * @return RSA公钥
     * @throws KeyStoreException 密钥库操作异常
     */
    public java.security.PublicKey getRSAPublicKey(String keyId) throws KeyStoreException {
        try {
            KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyId + ".public", new KeyStore.PasswordProtection(this.keyStorePassword));
            if (entry != null) {
                byte[] publicKeyBytes = entry.getSecretKey().getEncoded();
                java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
                java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(keySpec);
            }
            return null;
        } catch (Exception e) {
            throw new KeyStoreException("Failed to get RSA public key", e);
        }
    }

    /**
     * 删除密钥库中的指定条目
     *
     * @param alias 别名
     * @throws KeyStoreException 密钥库操作异常
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        keyStore.deleteEntry(alias);
    }

    /**
     * 关闭密钥库管理器
     */
    public void close() {
        // 清除敏感信息
        if (keyStorePassword != null) {
            Arrays.fill(keyStorePassword, '\0');
        }
        keyStore = null;
    }
}