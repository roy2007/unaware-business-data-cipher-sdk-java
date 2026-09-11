package com.unaware.cipher;

import com.unaware.cipher.common.utils.KeystorePathUtils;
import com.unaware.cipher.derivation.KeyDerivation;
import com.unaware.cipher.exception.EncryptionException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Objects;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

/**
 * UnawareCipherSuite的单元测试类
 *
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月16日 10:08
 */
public class UnawareCipherSuiteTest {
    private static final Logger logger = LoggerFactory.getLogger(UnawareCipherSuiteTest.class);


    // 定义路径模板和日期格式
    private static final String KEYSTORE_TEMPLATE = "bizSys/yunwuye-bizSys-{0}.jks";
    private static final String PID_FILE_TEMPLATE = "bizSys/yunwuye-bizSys-{0}.pid";
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
    private static final String TEST_KEYSTORE_PATH = String.valueOf(getTestKeystorePath());

    private static final String TEST_KEYSTORE_PASSWORD = "yunwuyeBizSysOther2024123!@#";
    private static final String TEST_ROOT_KEY_PASSWORD = "yunwuyeRootKey2024123!@#";
    private static final String TEST_SUBJECT_DOMAIN = "test-business-module";
    private static final int TEST_KEY_VERSION = 1;
    private static final String TEST_THIRD_PARTY_KEY_ID = "test-third-party-key";
    private static final String TEST_THIRD_PARTY_KEY_PASSWORD = "test-third-party-key-password";
    private static final String LOAD_KEYSTORE_PATH = "jks/yunwuye-bizSys-other.jks";

    private UnawareCipherSuite unwieldyCipherSuite;
    private File testKeyStoreFile;
    private File testKeyStoreFileChkSum;
    private SecretKey secretKey;

    @Before
    public void setUp() throws Exception {
        // 删除可能存在的旧测试文件
        testKeyStoreFile = new File(TEST_KEYSTORE_PATH);
        if (testKeyStoreFile.exists() && !testKeyStoreFile.delete()) {
            throw new Exception("无法删除测试testKeyStoreFile文件:" + testKeyStoreFile.getAbsolutePath());
        }
        testKeyStoreFileChkSum = new File(TEST_KEYSTORE_PATH + ".chksum");
        if (testKeyStoreFileChkSum.exists() && !testKeyStoreFileChkSum.delete()) {
            throw new Exception("无法删除测试testKeyStoreFileChkSum文件:" + testKeyStoreFileChkSum.getAbsolutePath());
        }
        secretKey = UnawareCipherSuite.getSecretKeyFromStr( "FPESecretKey1234", "AES");
    }

    @After
    public void tearDown() throws Exception {
        // 关闭cipherSuite
        if (unwieldyCipherSuite != null) {
            unwieldyCipherSuite.close();
        }
        // 删除测试文件
        if (testKeyStoreFile.exists() && !testKeyStoreFile.delete()) {
            throw new Exception("无法删除测试testKeyStoreFile文件:" + testKeyStoreFile.getAbsolutePath());
        }
        if (testKeyStoreFileChkSum.exists() && !testKeyStoreFileChkSum.delete()) {
            throw new Exception("无法删除测试testKeyStoreFileChkSum文件:" + testKeyStoreFileChkSum.getAbsolutePath());
        }
    }

    @Test
    public void testCreateNewCipherSuite() throws Exception {
        // 测试创建新的cipherSuite实例
        unwieldyCipherSuite = UnawareCipherSuite.createNew(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD);
        // 创建根密钥
        SecretKey newRootKey = unwieldyCipherSuite.createRootKey(TEST_ROOT_KEY_PASSWORD);

        String checksum = KeystorePathUtils.generateSHA256Checksum(TEST_KEYSTORE_PATH, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(TEST_KEYSTORE_PATH, checksum);

        // 获取根密钥
        SecretKey rootKey = unwieldyCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD);
        assertNotNull("根密钥应该不为空", rootKey);

        assertEquals("新创建根密钥与获取根密钥应该相同", UnawareCipherSuite.getSecretKeyStr(newRootKey), UnawareCipherSuite.getSecretKeyStr(rootKey));
        assertTrue("cipherSuite应该已经初始化", unwieldyCipherSuite.isInitialized());
        assertTrue("密钥库文件应该已经创建", testKeyStoreFile.exists());
    }

    @Test
    public void testCreateAndGetRootKey() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        // 获取根密钥
        SecretKey rootKey = unwieldyCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD);
        assertNotNull("默认根密钥应该不为空", rootKey);
        String rootKeyStr = UnawareCipherSuite.getSecretKeyStr(rootKey);
        System.out.println(rootKeyStr);


        String originChkSum = KeystorePathUtils.readChecksumFromFile(path + ".chksum");
        System.out.println("原始校验和：" + originChkSum);

        String myRootKey = "my_root_key";
        String myRootKeyPw ="my1234~!5^AZX";
        // 先删除相同keyId密钥
        unwieldyCipherSuite.deleteByKeyId(myRootKey, myRootKeyPw);
        String checksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(path, checksum);
        System.out.println("删除后重新计算校验和：" + checksum);

        // 保存指定RootKeyId根密钥必须32或16。 34asdf9876265201
        // 生成随机种子
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        // 需要转成Base64字符串
        String newRootKeyStr = Base64.getEncoder().encodeToString(seed);
        System.out.println(newRootKeyStr);

        // 保存KeyId
        SecretKey newRootKey = unwieldyCipherSuite.storeRootKey(myRootKey, newRootKeyStr, myRootKeyPw);
        String agingSaveKeyChecksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(path, agingSaveKeyChecksum);
        System.out.println("再次保存Key后重新计算校验和：" + agingSaveKeyChecksum);

        // 获取密钥
        SecretKey getNewRootKey = unwieldyCipherSuite.getRootKey(myRootKeyPw, myRootKey);
        String getNewRootKeyStr = UnawareCipherSuite.getSecretKeyStr(getNewRootKey);
        System.out.println(getNewRootKeyStr);
        assertNotNull("指定RootKeyId根密钥应该不为空(my_root_key)", getNewRootKey);
        assertEquals("新创建根密钥与获取根密钥应该相同", UnawareCipherSuite.getSecretKeyStr(newRootKey), UnawareCipherSuite.getSecretKeyStr(getNewRootKey));
        //
        // 关闭并重新加载cipherSuite
        unwieldyCipherSuite.close();

    }

    @Test(expected = EncryptionException.class)
    public void testLoadNonExistentKeyStore() throws Exception {
        // 测试加载不存在的密钥库
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(LOAD_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD);
        SecretKey retrievedRootKey = unwieldyCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD);
        String rootKey = UnawareCipherSuite.getSecretKeyStr(retrievedRootKey);
        System.out.println(rootKey);
    }

    @Test(expected = EncryptionException.class)
    public void testGetNonExistentRootKey() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 尝试获取不存在的根密钥
        unwieldyCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD+"123");
    }

    @Test
    public void testDeriveKey() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 获取根密钥
        SecretKey rootKey = unwieldyCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD);

        // 派生密钥
        SecretKey derivedKey = unwieldyCipherSuite.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        assertNotNull("派生的密钥应该不为空", derivedKey);
        assertNotEquals("派生的密钥不应该与根密钥相同", rootKey.getEncoded(), derivedKey.getEncoded());

        // 再次派生相同参数的密钥
        SecretKey derivedKey2 = unwieldyCipherSuite.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        assertEquals("相同参数派生的密钥应该相同", UnawareCipherSuite.getSecretKeyStr(derivedKey), UnawareCipherSuite.getSecretKeyStr(derivedKey2));

        // 派生不同参数的密钥
        SecretKey derivedKey3 = unwieldyCipherSuite.deriveKey(rootKey, "different-domain", TEST_KEY_VERSION);
        assertNotEquals("不同参数派生的密钥不应该相同", derivedKey.getEncoded(), derivedKey3.getEncoded());
    }

    @Test
    public void testThirdPartyKeyManagement() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        String reChecksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        String originChkSum = KeystorePathUtils.readChecksumFromFile(path + ".chksum");
        System.out.println("读取原始校验和：" + originChkSum);
        System.out.println("重新计算校验和：" + reChecksum);

        // 先删除相同keyId密钥
        unwieldyCipherSuite.deleteThirdPartyByKeyId(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);
        String checksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(path, checksum);
        System.out.println("删除后重新计算校验和：" + checksum);

        // 生成测试密钥，存储第三方密钥
        SecretKey testKey = unwieldyCipherSuite.generateSecretKey("AES", 256);
        unwieldyCipherSuite.storeThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, testKey, TEST_THIRD_PARTY_KEY_PASSWORD);
        unwieldyCipherSuite.saveKeyStore();

        checksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(path, checksum);
        System.out.println("新建第三方密钥后重新计算校验和：" + checksum);
        // 关闭并重新加载cipherSuite
        unwieldyCipherSuite.close();

        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        reChecksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        originChkSum = KeystorePathUtils.readChecksumFromFile(path + ".chksum");
        System.out.println("2读取原始校验和：" + originChkSum);
        System.out.println("2重新计算校验和：" + reChecksum);

        // 获取第三方密钥
        SecretKey retrievedKey = unwieldyCipherSuite.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);
        assertNotNull("获取的第三方密钥应该不为空", retrievedKey);
        assertEquals("第三方密钥应该相同", UnawareCipherSuite.getSecretKeyStr(testKey), UnawareCipherSuite.getSecretKeyStr(retrievedKey));
    }

    @Test
    public void testAESEncryptionCBC() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 生成密钥和IV
        SecretKey secretKey = unwieldyCipherSuite.generateSecretKey("AES", 256);
        byte[] iv = unwieldyCipherSuite.generateRandomIV(16);

        // 测试数据
        String plaintext = "Hello, yunwuye Encryption cipherSuite!";

        // 加密
        String ciphertext = unwieldyCipherSuite.aesEncryptCBC(plaintext, secretKey, iv);
        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);

        // 解密
        String decryptedText = unwieldyCipherSuite.aesDecryptCBC(ciphertext, secretKey, iv);
        assertEquals("解密后的文本应该与原文相同", plaintext, decryptedText);
    }

    @Test
    public void testAESEncryptionECB() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 生成密钥
        SecretKey secretKey = unwieldyCipherSuite.generateSecretKey("AES", 256);

        // 测试数据
        String plaintext = "Hello, yunwuye Encryption cipherSuite!";

        // 加密
        String ciphertext = unwieldyCipherSuite.aesEncryptECB(plaintext, secretKey);
        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);

        // 解密
        String decryptedText = unwieldyCipherSuite.aesDecryptECB(ciphertext, secretKey);
        assertEquals("解密后的文本应该与原文相同", plaintext, decryptedText);
    }

    @Test
    public void testRSAEncryption() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 生成RSA密钥对
        KeyPair keyPair = unwieldyCipherSuite.generateRSAKeyPair(2048);

        // 测试数据
        String plaintext = "Hello, RSA Encryption!";

        // 加密
        String ciphertext = unwieldyCipherSuite.rsaEncrypt(plaintext, keyPair.getPublic());
        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);

        // 解密
        String decryptedText = unwieldyCipherSuite.rsaDecrypt(ciphertext, keyPair.getPrivate());
        assertEquals("解密后的文本应该与原文相同", plaintext, decryptedText);
    }

    @Test
    public void testRSASignature() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 生成RSA密钥对
        KeyPair keyPair = unwieldyCipherSuite.generateRSAKeyPair(2048);

        // 测试数据
        String data = "Hello, RSA Signature!";

        // 生成签名
        String signature = unwieldyCipherSuite.rsaSign(data, keyPair.getPrivate(), "SHA256withRSA");
        assertNotNull("签名应该不为空", signature);

        // 验证签名
        boolean isValid = unwieldyCipherSuite.rsaVerify(data, signature, keyPair.getPublic(), "SHA256withRSA");
        assertTrue("签名应该有效", isValid);

        // 验证伪造的签名
        boolean isInvalid = unwieldyCipherSuite.rsaVerify("tampered data", signature, keyPair.getPublic(), "SHA256withRSA");
        assertFalse("伪造的签名应该无效", isInvalid);
    }

    @Test
    public void testHashFunctions() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 测试数据
        String data = "Hello, Hash Functions!";

        // SHA-256哈希
        String sha256Hash = unwieldyCipherSuite.hashSHA256(data);
        assertNotNull("SHA-256哈希应该不为空", sha256Hash);
        assertEquals("SHA-256哈希长度应该正确", 44, sha256Hash.length()); // Base64编码的32字节哈希

        // SHA-512哈希
        String sha512Hash = unwieldyCipherSuite.hashSHA512(data);
        assertNotNull("SHA-512哈希应该不为空", sha512Hash);
        assertEquals("SHA-512哈希长度应该正确", 88, sha512Hash.length()); // Base64编码的64字节哈希

        // 相同数据的哈希应该相同
        String sha256Hash2 = unwieldyCipherSuite.hashSHA256(data);
        assertEquals("相同数据的SHA-256哈希应该相同", sha256Hash, sha256Hash2);

        // 不同数据的哈希应该不同
        String sha256Hash3 = unwieldyCipherSuite.hashSHA256("different data");
        assertNotEquals("不同数据的SHA-256哈希应该不同", sha256Hash, sha256Hash3);
    }

    @Test
    public void testFPEEncryption() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        //tweak
        byte[] tweak = unwieldyCipherSuite.generateRandomTweak();
        // 测试数据
        String plaintext = "13439298452";
        // FPE加密
        String ciphertext = unwieldyCipherSuite.fpeEncrypt(plaintext, tweak, secretKey);
        System.out.println("Original: " + plaintext);
        System.out.println("fpeEncrypt: " + ciphertext);

        // FPE解密
        String decryptedText = unwieldyCipherSuite.fpeDecrypt(ciphertext, tweak, secretKey);
        System.out.println("fpeDecrypt: " + decryptedText);
        System.out.println("  Original: " + plaintext);

        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);
        assertEquals("密文长度应该与明文相同", plaintext.length(), ciphertext.length());
    }

    @Test
    public void testFpeEncryptPhone() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        //tweak
        byte[] tweak = unwieldyCipherSuite.generateRandomTweak();
        // 测试数据
        String plaintext = "13439298452";

        // FPE加密
        String ciphertext = unwieldyCipherSuite.fpeEncryptPhone(plaintext, tweak, secretKey);
        System.out.println("Original: " + plaintext);
        System.out.println("fpeEncrypt: " + ciphertext);

        // FPE解密
        String decryptedText = unwieldyCipherSuite.fpeDecrypt(ciphertext, tweak, secretKey);
        System.out.println("fpeDecrypt: " + decryptedText);
        System.out.println("  Original: " + plaintext);

        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);
        assertEquals("密文长度应该与明文相同", plaintext.length(), ciphertext.length());
    }

    @Test
    public void testFpeEncryptIdCard() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        //tweak
        byte[] tweak = unwieldyCipherSuite.generateRandomTweak();
        // 测试数据
        String plaintext = "42112519900101001X";
        // FPE加密
        String ciphertext = unwieldyCipherSuite.fpeEncryptIdCard(plaintext, tweak, secretKey);
        System.out.println("Original: " + plaintext);
        System.out.println("fpeEncrypt: " + ciphertext);

        // FPE解密
        String decryptedText = unwieldyCipherSuite.fpeDecrypt(ciphertext, tweak, secretKey);
        System.out.println("fpeDecrypt: " + decryptedText);
        System.out.println("  Original: " + plaintext);

        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);
        assertEquals("密文长度应该与明文相同", plaintext.length(), ciphertext.length());
    }

    @Test
    public void testFpeEncryptEmailLocal() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        //tweak
        byte[] tweak = unwieldyCipherSuite.generateRandomTweak();
        // 测试数据
        String plaintext1 = "13439298452@163.com";
        String plaintext = "Roy-rui2007@163.com";

        // FPE加密
        String ciphertext = unwieldyCipherSuite.fpeEncryptEmailLocal(plaintext, tweak, secretKey);
        System.out.println("Original: " + plaintext);
        System.out.println("fpeEncrypt: " + ciphertext);

        // FPE解密
        String decryptedText = unwieldyCipherSuite.fpeDecrypt(ciphertext, tweak, secretKey);
        System.out.println("fpeDecrypt: " + decryptedText);
        System.out.println("  Original: " + plaintext);

        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);
        assertEquals("密文长度应该与明文相同", plaintext.length(), ciphertext.length());
    }

    @Test
    public void testFPEWithCustomCharset() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        // 生成tweak
        byte[] tweak = unwieldyCipherSuite.generateRandomTweak();
        // 自定义字符集（小写字母）
        String charset = "abcdefghijklmnopqrstuvwxyz.-_=";
        // 测试数据
        String plaintext = "明文roy.rui";
        // 测试数据错误 方 法 ： 中 文 不 应 该 包 含 在 自 定 义 字 符 集 中
        String plaintext1 = "明文我的时间丢了";
        // FPE加密
        String ciphertext = unwieldyCipherSuite.fpeEncrypt(plaintext, charset, tweak, secretKey);
        System.out.println("Original: " + plaintext);
        System.out.println("fpeEncrypt: " + ciphertext);

        // FPE解密
        String decryptedText = unwieldyCipherSuite.fpeDecrypt(ciphertext, tweak, secretKey);
        System.out.println("fpeDecrypt: " + decryptedText);
        System.out.println("  Original: " + plaintext);

        assertNotNull("加密后的密文应该不为空", ciphertext);
        assertNotEquals("密文不应该与明文相同", plaintext, ciphertext);
        assertEquals("密文长度应该与明文相同", plaintext.length(), ciphertext.length());

    }

    @Test
    public void testCacheManagement() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 先删除相同keyId密钥
        unwieldyCipherSuite.deleteThirdPartyByKeyId(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);
        String checksum = KeystorePathUtils.generateSHA256Checksum(path, UnawareCipherSuite.getVersion(), UnawareCipherSuite.getName());
        KeystorePathUtils.saveChecksumToFile(path, checksum);
        System.out.println("删除后重新计算校验和：" + checksum);

        // 生成密钥
        SecretKey secretKey = unwieldyCipherSuite.generateSecretKey("AES", 256);
        // 存储第三方密钥
        unwieldyCipherSuite.storeThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, secretKey, TEST_THIRD_PARTY_KEY_PASSWORD);
        unwieldyCipherSuite.saveKeyStore();

        // 启用缓存
        unwieldyCipherSuite.enableCache();

        // 获取密钥（应该缓存）
        SecretKey key1 = unwieldyCipherSuite.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);

        // 再次获取密钥（应该从缓存中获取）
        SecretKey key2 = unwieldyCipherSuite.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);

        // 两个密钥应该相同（引用相同）
        assertSame("两次获取的密钥应该相同（缓存）", key1, key2);

        // 清除缓存
        unwieldyCipherSuite.clearCache();

        // 再次获取密钥（应该重新从密钥库中获取）
        SecretKey key3 = unwieldyCipherSuite.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);

        // 密钥应该相同（内容相同）但引用不同
        assertEquals("密钥内容应该相同", UnawareCipherSuite.getSecretKeyStr(key1), UnawareCipherSuite.getSecretKeyStr(key3));
        assertNotSame("引用应该不同（缓存已清除）", key1, key3);

        // 禁用缓存
        unwieldyCipherSuite.disableCache();

        // 再次获取密钥
        SecretKey key4 = unwieldyCipherSuite.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ID, TEST_THIRD_PARTY_KEY_PASSWORD);

        // 密钥应该相同（内容相同）但引用不同
        assertEquals("密钥内容应该相同", UnawareCipherSuite.getSecretKeyStr(key1), UnawareCipherSuite.getSecretKeyStr(key4));
        assertNotSame("引用应该不同（缓存已禁用）", key3, key4);
    }

    @Test
    public void testGenerateRandomIV() throws Exception {
        // 创建新的cipherSuite实例
        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        unwieldyCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);

        // 生成IV
        byte[] iv1 = unwieldyCipherSuite.generateRandomIV(16);
        byte[] iv2 = unwieldyCipherSuite.generateRandomIV(16);

        assertNotNull("IV应该不为空", iv1);
        assertEquals("IV长度应该正确", 16, iv1.length);

        // 两次生成的IV应该不同
        assertNotEquals("两次生成的IV应该不同", iv1, iv2);
    }

    @Test
    public void testcipherSuiteVersionAndName() throws Exception {
        // 测试cipherSuite版本和名称
        assertEquals("版本应该正确", "0.0.1-SNAPSHOT", UnawareCipherSuite.getVersion());
        assertEquals("名称应该正确", "yunwuye Encryption cipherSuite for Java", UnawareCipherSuite.getName());
    }

    @Test
    public void testBase64Encoding() throws Exception {

        String password = "S+51nL&tD>t:HHCz";
        Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8));

        String rookKeyPassword = "2!W!#as21!@#";
        Base64.getEncoder().encodeToString(rookKeyPassword.getBytes(StandardCharsets.UTF_8));
        // 转换为Base64字符串
        String keyStorePwBase64 = UnawareCipherSuite.getBase64Str(TEST_KEYSTORE_PASSWORD);
        String rootKeyBase64 = UnawareCipherSuite.getBase64Str(TEST_ROOT_KEY_PASSWORD);

        // 从Base64字符串转换回密钥
        String keyStorePw = UnawareCipherSuite.getPasswordFromBase64(keyStorePwBase64);
        String rootKey = UnawareCipherSuite.getPasswordFromBase64(rootKeyBase64);


        // 原始密钥和解码后的密钥应该相同
        assertEquals("原始密钥和解码后的密钥应该相同", TEST_KEYSTORE_PASSWORD, keyStorePw);
        assertEquals("原始密钥和解码后的密钥应该相同", TEST_ROOT_KEY_PASSWORD, rootKey);

        // 创建根密钥
        // 生成随机种子
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        // 创建根密钥
        SecretKey rootSecretKey = KeyDerivation.createRootKey(seed);
        // 记录根密钥
        System.out.println("创建根密钥: " + Base64.getEncoder().encodeToString(rootSecretKey.getEncoded()));
    }

    public static long getCurrentPid() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        String name = runtimeMXBean.getName(); // 格式通常为 "12345@hostname"
        try {
            return Long.parseLong(name.split("@")[0]);
        } catch (Exception e) {
            throw new RuntimeException("无法获取当前进程 PID", e);
        }
    }

    public static boolean checkPid() throws IOException {
        // 1. 获取当前进程的 PID
        long currentPid = getCurrentPid();

        // 2. 构建 PID 标记文件的路径
        Path pidFilePath = Paths.get(MessageFormat.format(PID_FILE_TEMPLATE, currentPid));

        // 3. 确保父目录存在
        Files.createDirectories(pidFilePath.getParent());


        // 4. 【孤儿文件清理】检查是否存在其他进程留下的孤儿 PID 文件
        // 遍历 bizSys 目录下所有的 .pid 文件
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(pidFilePath.getParent(), "*.pid")) {
            for (Path existingPidFile : stream) {
                // 读取文件内容，获取之前写入的 PID
                String fileContent = new String(Files.readAllBytes(existingPidFile), StandardCharsets.UTF_8).trim();
                try {
                    long oldPid = Long.parseLong(fileContent);
                    // 如果文件里的 PID 不是当前进程，且该进程已经不存在，说明是孤儿文件
                    if (oldPid != currentPid) {
                        System.out.println("检测到孤儿 PID 文件，强制清理: " + existingPidFile);
                        Files.delete(existingPidFile);
                    }
                } catch (NumberFormatException e) {
                    // 如果文件内容损坏，也直接删除
                    Files.delete(existingPidFile);
                }
            }
        }

        // 5. 检查当前进程的 PID 文件是否已存在
        if (Files.exists(pidFilePath)) {
            logger.info("当前进程已生成过pid文件:{}，跳过生成。", pidFilePath);
            return true;
        }

        // 6. 【原子性创建】使用 CREATE_NEW 选项，防止多线程并发创建
        Files.write(pidFilePath, String.valueOf(currentPid).getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
        return false;
    }

    /**
     * 动态获取真实路径（兼容所有操作系统）
     */
    @SuppressWarnings("ConstantConditions")
    private static Path getTestKeystorePath() {
        String baseName = "root";
        try {
//            if (!checkPid()) {
//
//            }
            Path currentPath = Paths.get(MessageFormat.format(KEYSTORE_TEMPLATE, baseName));

            // 2. 如果固定的文件已经存在，直接返回，绝不重复生成
            if (Files.exists(currentPath)) {
                logger.info("复用已有证书: {}", currentPath.toAbsolutePath());
                return currentPath;
            }

            // 3. 如果不存在，生成带时间戳的新文件
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
            String newName = baseName + "-" + timestamp;
            Path newPath = Paths.get(MessageFormat.format(KEYSTORE_TEMPLATE, newName));

            Files.createDirectories(newPath.getParent());
            Files.createFile(newPath);

            System.out.println("首次生成证书: " + newPath.toAbsolutePath());
            return newPath;
        } catch (IOException e) {
            // 1. 记录带有上下文的日志（而不是 e.printStackTrace()）
            logger.error("生成 Keystore 文件失败", e);

            // 2. 根据业务需求决定：是返回 null、抛出业务异常，还是重试
            throw new RuntimeException("Keystore 生成失败，请检查目录权限", e);
        }
    }
}
