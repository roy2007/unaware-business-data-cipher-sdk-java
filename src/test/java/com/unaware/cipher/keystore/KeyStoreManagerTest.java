package com.unaware.cipher.keystore;

import com.unaware.cipher.UnawareCipherSuite;
import com.unaware.cipher.exception.EncryptionException;
import com.unaware.cipher.exception.ErrorCode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * KeyStoreManager的单元测试类
 */
public class KeyStoreManagerTest {

    private static final String TEST_KEYSTORE_PATH = "test-keystore-manager.jks";
    private static final String TEST_KEYSTORE_PASSWORD = "test-keystore-password";
    private static final String TEST_ROOT_KEY_ALIAS = "root-key";
    private static final String TEST_ROOT_KEY_PASSWORD = "test-root-key-password";
    private static final String TEST_THIRD_PARTY_KEY_ALIAS = "third-party-key";
    private static final String TEST_THIRD_PARTY_KEY_PASSWORD = "test-third-party-key-password";
    private static final String TEST_RSA_KEY_ALIAS = "rsa-key";
    private static final String TEST_RSA_KEY_PASSWORD = "test-rsa-key-password";

    private KeyStoreManager keyStoreManager;
    private File testKeyStoreFile;

    @Before
    public void setUp() throws Exception {
        // 删除可能存在的旧测试文件
        testKeyStoreFile = new File(TEST_KEYSTORE_PATH);
        if (testKeyStoreFile.exists() && !testKeyStoreFile.delete()) {
            throw new Exception("无法删除测试testKeyStoreFile文件:" + testKeyStoreFile.getAbsolutePath());
        }
    }

    @After
    public void tearDown() throws Exception {
        // 关闭密钥库管理器
        if (keyStoreManager != null) {
            keyStoreManager.close();
        }
    }

    @Test
    public void testCreateNewKeyStore() throws Exception {
        // 测试创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        assertTrue("密钥库文件应该已经创建", testKeyStoreFile.exists());
    }

    @Test(expected = FileNotFoundException.class)
    public void testLoadNonExistentKeyStore() throws Exception {
        // 测试加载不存在的密钥库
        new KeyStoreManager("non-existent-keystore.jks", TEST_KEYSTORE_PASSWORD, false);
    }

    @Test
    public void testStoreAndGetRootKey() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 生成根密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey rootKey = keyGen.generateKey();
        
        // 存储根密钥
        keyStoreManager.storeRootKey(rootKey, TEST_ROOT_KEY_PASSWORD);
        keyStoreManager.saveKeyStore();
        
        // 关闭并重新加载密钥库
        keyStoreManager.close();
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, false);
        
        // 获取根密钥
        SecretKey retrievedRootKey = keyStoreManager.getRootKey(TEST_ROOT_KEY_PASSWORD);
        assertNotNull("获取的根密钥应该不为空", retrievedRootKey);
        assertArrayEquals("根密钥应该相同", rootKey.getEncoded(), retrievedRootKey.getEncoded());
    }

    @Test
    public void testGetNonExistentRootKey() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 尝试获取不存在的根密钥
        SecretKey rootKey = keyStoreManager.getRootKey(TEST_ROOT_KEY_PASSWORD);
        assertEquals("获取的根密钥应该为空", null, rootKey);
    }

    @Test
    public void testStoreAndGetThirdPartyKey() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);

        // 生成第三方密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey thirdPartyKey = keyGen.generateKey();
        
        // 存储第三方密钥
        keyStoreManager.storeThirdPartyKey(TEST_THIRD_PARTY_KEY_ALIAS, thirdPartyKey, TEST_THIRD_PARTY_KEY_PASSWORD);
        keyStoreManager.saveKeyStore();
        
        // 关闭并重新加载密钥库
        keyStoreManager.close();
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, false);
        
        // 获取第三方密钥
        SecretKey retrievedThirdPartyKey = keyStoreManager.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ALIAS, TEST_THIRD_PARTY_KEY_PASSWORD);
        assertNotNull("获取的第三方密钥应该不为空", retrievedThirdPartyKey);
        assertArrayEquals("第三方密钥应该相同", thirdPartyKey.getEncoded(), retrievedThirdPartyKey.getEncoded());
    }

    @Test
    public void testStoreAndGetMoreThirdPartyKeySize() throws Exception {
        // 假设最大密钥数量为500（根据实际业务逻辑调整）
        int maxKeyCount = 500;

        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);

        // 循环存储第三方密钥
        for (int i = 0; i < maxKeyCount; i++) {
            // 生成第三方密钥
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey thirdPartyKey = keyGen.generateKey();

            // 构造唯一的别名
            String alias = TEST_THIRD_PARTY_KEY_ALIAS + "-" + i;
            String password = TEST_THIRD_PARTY_KEY_PASSWORD + "-" + i;

            System.out.println("Storing 第三方key: " + alias+ ", password: "+  password+ "thirdPartyKey:" + UnawareCipherSuite.getSecretKeyStr(thirdPartyKey));
            // 存储第三方密钥
            keyStoreManager.storeThirdPartyKey(alias, thirdPartyKey, password);
        }

        // 保存密钥库
        keyStoreManager.saveKeyStore();

        // 关闭并重新加载密钥库
        keyStoreManager.close();
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, false);

        // 验证所有密钥都能成功读取
        for (int i = 0; i < maxKeyCount; i++) {
            String alias = TEST_THIRD_PARTY_KEY_ALIAS + "-" + i;
            String password = TEST_THIRD_PARTY_KEY_PASSWORD + "-" + i;

            SecretKey retrievedKey = keyStoreManager.getThirdPartyKey(alias, password);
            System.out.println("Storing2第三方key: " + alias+ ", password: "+  password+ "thirdPartyKey:" + UnawareCipherSuite.getSecretKeyStr(retrievedKey));
            assertNotNull("第" + i + "个密钥应该不为空", retrievedKey);
        }

        // 尝试存储超过最大数量的密钥（验证边界条件）
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey extraKey = keyGen.generateKey();

            keyStoreManager.storeThirdPartyKey("extra-key", extraKey, "extra-password");
            //fail("应该抛出异常，因为已达到最大密钥数量限制");
        } catch (EncryptionException e) {
            assertEquals("错误码应该是KEY_STORE_MAX_LIMIT_EXCEEDED", ErrorCode.KEY_STORE_MAX_LIMIT_EXCEEDED, e.getErrorCode());
        }
    }


    @Test
    public void testGetNonExistentThirdPartyKey() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 尝试获取不存在的第三方密钥
        SecretKey nonExistKey = keyStoreManager.getThirdPartyKey("non-existent-key", TEST_THIRD_PARTY_KEY_PASSWORD);
        assertEquals("获取的第三方密钥应该为空", null, nonExistKey);
    }

    @Test
    public void testStoreAndGetRSAKeyPair() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 生成RSA密钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        // 存储RSA密钥对
        keyStoreManager.storeRSAKeyPair(TEST_RSA_KEY_ALIAS, keyPair, TEST_RSA_KEY_PASSWORD);
        keyStoreManager.saveKeyStore();
        
        // 关闭并重新加载密钥库
        keyStoreManager.close();
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, false);
        
        // 获取RSA私钥
//        PrivateKey privateKey = keyStoreManager.getRSAPrivateKey(TEST_RSA_KEY_ALIAS, TEST_RSA_KEY_PASSWORD);
//        assertNotNull("获取的RSA私钥应该不为空", privateKey);
//        assertArrayEquals("RSA私钥应该相同", keyPair.getPrivate().getEncoded(), privateKey.getEncoded());
        
        // 获取RSA公钥
        PublicKey publicKey = keyStoreManager.getRSAPublicKey(TEST_RSA_KEY_ALIAS);
        assertNotNull("获取的RSA公钥应该不为空", publicKey);
        assertArrayEquals("RSA公钥应该相同", keyPair.getPublic().getEncoded(), publicKey.getEncoded());
    }

    //@Test
    public void testStoreAndGetCertificate() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 生成RSA密钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        // 创建自签名证书
        X509Certificate cert = createSelfSignedCertificate(keyPair);
        
        // 存储证书
        keyStoreManager.storeCertificate("test-cert", cert);
        keyStoreManager.saveKeyStore();
        
        // 关闭并重新加载密钥库
        keyStoreManager.close();
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, false);
        
        // 获取证书
        Certificate retrievedCert = keyStoreManager.getCertificate("test-cert");
        assertNotNull("获取的证书应该不为空", retrievedCert);
        assertArrayEquals("证书应该相同", cert.getEncoded(), retrievedCert.getEncoded());
    }

    @Test
    public void testGetNonExistentCertificate() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 尝试获取不存在的证书
        Certificate cert = keyStoreManager.getCertificate("non-existent-cert");
        assertEquals("获取的证书应该为空", null, cert);
    }

    @Test
    public void testDeleteEntry() throws Exception {
        // 创建新的密钥库
        keyStoreManager = new KeyStoreManager(TEST_KEYSTORE_PATH, TEST_KEYSTORE_PASSWORD, true);
        
        // 生成并存储第三方密钥
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey thirdPartyKey = keyGen.generateKey();

        keyStoreManager.storeThirdPartyKey(TEST_THIRD_PARTY_KEY_ALIAS, thirdPartyKey, TEST_THIRD_PARTY_KEY_PASSWORD);
        keyStoreManager.saveKeyStore();
        
        // 验证密钥存在
        SecretKey retrievedKey = keyStoreManager.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ALIAS, TEST_THIRD_PARTY_KEY_PASSWORD);
        assertNotNull("密钥应该存在", retrievedKey);
        
        // 删除密钥
        keyStoreManager.deleteThirdPartyByKeyId(TEST_THIRD_PARTY_KEY_ALIAS);
        keyStoreManager.saveKeyStore();
        
        // 验证密钥已删除
        try {
            SecretKey deletedKey = keyStoreManager.getThirdPartyKey(TEST_THIRD_PARTY_KEY_ALIAS, TEST_THIRD_PARTY_KEY_PASSWORD);
            assertEquals("删除的密钥应该为空", null, deletedKey);
        } catch (EncryptionException e) {
            assertEquals("错误码应该是KEY_STORE_ENTRY_NOT_FOUND", ErrorCode.KEY_STORE_ENTRY_NOT_FOUND, e.getErrorCode());
        }
    }

    /**
     * 创建自签名证书
     */
    private X509Certificate createSelfSignedCertificate(KeyPair keyPair) throws Exception {
        // 使用Bouncy Castle生成自签名证书
        return null; // 在实际测试中，我们可以使用Bouncy Castle库生成证书
    }
}
