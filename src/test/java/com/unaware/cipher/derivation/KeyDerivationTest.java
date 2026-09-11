package com.unaware.cipher.derivation;

import com.unaware.cipher.UnawareCipherSuite;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * KeyDerivation的单元测试类
 */
public class KeyDerivationTest {

    private static final String TEST_SUBJECT_DOMAIN = "test-business-module";
    private static final int TEST_KEY_VERSION = 1;
    private static final String TEST_SUBJECT_DOMAIN_2 = "another-business-module";
    private static final int TEST_KEY_VERSION_2 = 2;

    @Test
    public void testCreateRootKey() throws Exception {
        // 生成随机种子
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        
        // 创建根密钥
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        assertNotNull("根密钥应该不为空", rootKey);
        assertEquals("根密钥算法应该是AES", "AES", rootKey.getAlgorithm());
        assertEquals("根密钥长度应该是256位", 32, rootKey.getEncoded().length); // 32字节 = 256位
    }

    @Test
    public void testCreateRootKeyWithInvalidSeed() throws Exception {
        // 使用无效的种子（长度不足）
        byte[] invalidSeed = new byte[16]; // 16字节太短
        SecretKey deriveKey = KeyDerivation.createRootKey(invalidSeed);
        System.out.println(UnawareCipherSuite.getSecretKeyStr(deriveKey));
    }

    @Test
    public void testDeriveKey() throws Exception {
        // 创建根密钥
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        // 从根密钥派生业务模块专用密钥
        SecretKey derivedKey = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        
        assertNotNull("派生的密钥应该不为空", derivedKey);
        assertEquals("派生密钥算法应该是AES", "AES", derivedKey.getAlgorithm());
        assertEquals("派生密钥长度应该是256位", 32, derivedKey.getEncoded().length);
        assertNotEquals("派生密钥不应该与根密钥相同", rootKey.getEncoded(), derivedKey.getEncoded());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveKeyWithInvalidRootKey() throws Exception {
        // 使用无效的根密钥（非AES算法）
        byte[] invalidKeyBytes = new byte[32];
        SecretKey invalidKey = new javax.crypto.spec.SecretKeySpec(invalidKeyBytes, "DES");
        SecretKey derivedKey = KeyDerivation.deriveKey(invalidKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        assertNotNull("派生的密钥应该不为空", derivedKey);
        System.out.println(UnawareCipherSuite.getSecretKeyStr(derivedKey));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveKeyWithInvalidSubjectDomain() throws Exception {
        // 创建根密钥
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        // 使用无效的主题域（null）
        KeyDerivation.deriveKey(rootKey, null, TEST_KEY_VERSION);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveKeyWithInvalidKeyVersion() throws Exception {
        // 创建根密钥
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        // 使用无效的密钥版本（负数）
        KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, -1);
    }

    @Test
    public void testDeriveKeyWithSameParameters() throws Exception {
        // 创建根密钥
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        // 使用相同的参数派生两次密钥
        SecretKey derivedKey1 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        SecretKey derivedKey2 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        
        // 两次派生的密钥应该相同
        assertArrayEquals("使用相同参数派生的密钥应该相同", derivedKey1.getEncoded(), derivedKey2.getEncoded());
    }

    @Test
    public void testDeriveKeyWithDifferentParameters() throws Exception {
        // 创建根密钥
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        SecretKey rootKey = KeyDerivation.createRootKey(seed);
        
        // 使用不同的参数派生密钥
        SecretKey derivedKey1 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        SecretKey derivedKey2 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN_2, TEST_KEY_VERSION);
        SecretKey derivedKey3 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION_2);
        SecretKey derivedKey4 = KeyDerivation.deriveKey(rootKey, TEST_SUBJECT_DOMAIN_2, TEST_KEY_VERSION_2);
        
        // 不同参数派生的密钥应该不同
        assertNotEquals("不同主题域派生的密钥应该不同", derivedKey1.getEncoded(), derivedKey2.getEncoded());
        assertNotEquals("不同密钥版本派生的密钥应该不同", derivedKey1.getEncoded(), derivedKey3.getEncoded());
        assertNotEquals("完全不同参数派生的密钥应该不同", derivedKey1.getEncoded(), derivedKey4.getEncoded());
    }

    @Test
    public void testDeriveKeyWithDifferentRootKeys() throws Exception {
        // 创建两个不同的根密钥
        byte[] seed1 = new byte[32];
        new SecureRandom().nextBytes(seed1);
        SecretKey rootKey1 = KeyDerivation.createRootKey(seed1);
        
        byte[] seed2 = new byte[32];
        new SecureRandom().nextBytes(seed2);
        SecretKey rootKey2 = KeyDerivation.createRootKey(seed2);
        
        // 使用相同的参数从不同的根密钥派生密钥
        SecretKey derivedKey1 = KeyDerivation.deriveKey(rootKey1, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        SecretKey derivedKey2 = KeyDerivation.deriveKey(rootKey2, TEST_SUBJECT_DOMAIN, TEST_KEY_VERSION);
        
        // 从不同根密钥派生的密钥应该不同
        assertNotEquals("从不同根密钥派生的密钥应该不同", derivedKey1.getEncoded(), derivedKey2.getEncoded());
    }
}
