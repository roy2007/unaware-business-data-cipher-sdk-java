# Unaware Cipher Suite SDK for Java （无感知数据加密SDK）

 是一个基于 Java 1.8 开发的加密软件开发工具包，提供了全面的加解密功能。针对密钥管理、标准加密算法和格式保留加密(FPE)等功能提供了完整的测试用例。

## 功能特点

- **JCEKS密钥存储库管理**：安全管理根密钥、第三方密钥和证书
- **密钥派生**：基于主题域的密钥派生机制，支持密钥版本管理
- **密钥与证书检索**：提供高效的密钥检索接口和缓存机制
- **标准加密算法**：支持AES、RSA、SHA-256、SHA-512等国际标准算法
- **FPE(格式保留加密)**：支持自定义字符集的格式保留加密，确保数据格式一致性
- **完善的异常处理**：提供完整的错误码体系和异常处理机制

## 快速开始

### 1. 添加Maven依赖

将以下依赖添加到您的pom.xml文件中：

```xml

<dependency>
    <groupId>com.unaware</groupId>
    <artifactId>business-data-cipher-sdk-java</artifactId>
    <version>1.0.1-SNAPSHOT</version>
</dependency>
```

### 2. 初始化SDK

```java
import com.unaware.cipher.yunwuyeEncryptionSDK;
import com.unaware.cipher.exception.EncryptionException;

public class QuickStartExample {
    public static void main(String[] args) {
        try {
            // 创建新的密钥库（或使用yunwuyeEncryptionSDK.loadExisting加载现有密钥库）
            yunwuyeEncryptionSDK sdk = yunwuyeEncryptionSDK.createNew("keystore.jks", "keystore-password");

            // 创建并存储根密钥
            sdk.createRootKey("root-key-password");

            // 保存更改
            sdk.saveKeyStore();

            System.out.println("SDK初始化成功");

            // 使用完毕后关闭SDK
            sdk.close();
        } catch (EncryptionException e) {
            System.err.println("SDK初始化失败: " + e.getMessage());
        }
    }
}
```

## 核心功能

### 1. 密钥管理

#### 创建和获取根密钥

```java
// 创建根密钥
SecretKey rootKey = sdk.createRootKey("root-key-password");

// 获取根密钥
SecretKey retrievedRootKey = sdk.getRootKey("root-key-password");
```

#### 密钥派生

```java
// 从根密钥派生业务模块专用密钥
SecretKey businessKey = sdk.deriveKey(rootKey, "user-service", 1);
```

#### 第三方密钥管理

```java
// 生成并存储第三方密钥
SecretKey thirdPartyKey = sdk.generateSecretKey("AES", 256);
sdk.storeThirdPartyKey("payment-service-key", thirdPartyKey, "third-party-key-password");

// 获取第三方密钥
SecretKey retrievedThirdPartyKey = sdk.getThirdPartyKey("payment-service-key", "third-party-key-password");
```

### 2. 标准加密算法

#### AES加密/解密

```java
// 生成密钥和IV
SecretKey secretKey = sdk.generateSecretKey("AES", 256);
byte[] iv = sdk.generateRandomIV(16);

// CBC模式加密
String plaintext = "Hello, yunwuye Encryption SDK!";
String ciphertext = sdk.aesEncryptCBC(plaintext, secretKey, iv);
System.out.println("加密后的密文: " + ciphertext);

// CBC模式解密
String decryptedText = sdk.aesDecryptCBC(ciphertext, secretKey, iv);
System.out.println("解密后的明文: " + decryptedText);

// ECB模式加密
String ciphertextECB = sdk.aesEncryptECB(plaintext, secretKey);
System.out.println("ECB模式加密后的密文: " + ciphertextECB);

// ECB模式解密
String decryptedTextECB = sdk.aesDecryptECB(ciphertextECB, secretKey);
System.out.println("ECB模式解密后的明文: " + decryptedTextECB);
```

#### RSA加密/解密

```java
// 生成RSA密钥对
KeyPair rsaKeyPair = sdk.generateRSAKeyPair(2048);

// 加密
String plaintext = "Hello, RSA Encryption!";
String ciphertext = sdk.rsaEncrypt(plaintext, rsaKeyPair.getPublic());
System.out.println("加密后的密文: " + ciphertext);

// 解密
String decryptedText = sdk.rsaDecrypt(ciphertext, rsaKeyPair.getPrivate());
System.out.println("解密后的明文: " + decryptedText);
```

#### RSA数字签名

```java
// 生成签名
String data = "Hello, RSA Signature!";
String signature = sdk.rsaSign(data, rsaKeyPair.getPrivate(), "SHA256withRSA");
System.out.println("生成的签名: " + signature);

// 验证签名
boolean isValid = sdk.rsaVerify(data, signature, rsaKeyPair.getPublic(), "SHA256withRSA");
System.out.println("签名验证结果: " + (isValid ? "有效" : "无效"));
```

#### 哈希算法

```java
String data = "Hello, Hash Functions!";

// SHA-256哈希
String sha256Hash = sdk.hashSHA256(data);
System.out.println("SHA-256哈希值: " + sha256Hash);

// SHA-512哈希
String sha512Hash = sdk.hashSHA512(data);
System.out.println("SHA-512哈希值: " + sha512Hash);
```

### 3. FPE(格式保留加密)

```java
// 生成密钥和tweak
SecretKey fpeKey = sdk.generateSecretKey("AES", 256);
byte[] tweak = sdk.generateRandomTweak();

// 数字加密（使用默认字符集0-9）
String plaintext = "1234567890";
String ciphertext = sdk.fpeEncrypt(plaintext, fpeKey, tweak);
System.out.println("加密后的密文: " + ciphertext);

// 数字解密
String decryptedText = sdk.fpeDecrypt(ciphertext, fpeKey, tweak);
System.out.println("解密后的明文: " + decryptedText);

// 使用自定义字符集（小写字母）
String customCharset = "abcdefghijklmnopqrstuvwxyz";
String textToEncrypt = "abcdefghij";
String ciphertextCustom = sdk.fpeEncrypt(textToEncrypt, fpeKey, customCharset, tweak);
System.out.println("使用自定义字符集加密后的密文: " + ciphertextCustom);

String decryptedTextCustom = sdk.fpeDecrypt(ciphertextCustom, fpeKey, customCharset, tweak);
System.out.println("使用自定义字符集解密后的明文: " + decryptedTextCustom);
```

### 4. 密钥缓存管理

```java
// 启用缓存（默认禁用）
sdk.enableCache();

// 禁用缓存
sdk.disableCache();

// 清除缓存
sdk.clearCache();
```

## 异常处理

SDK使用`EncryptionException`类处理异常，包含错误码和详细信息：

```java
try {
    // SDK操作
} catch (EncryptionException e) {
    System.err.println("错误码: " + e.getErrorCode());
    System.err.println("错误信息: " + e.getMessage());
    e.printStackTrace();
}
```

常见错误码：

- **GENERAL_ERROR (1000)**：通用错误
- **INVALID_PARAMETER (1001)**：无效参数
- **KEY_STORE_CREATE_ERROR (2000)**：创建密钥库失败
- **KEY_STORE_LOAD_ERROR (2001)**：加载密钥库失败
- **ROOT_KEY_CREATE_ERROR (3000)**：创建根密钥失败
- **ENCRYPTION_ERROR (5000)**：加密操作失败
- **DECRYPTION_ERROR (5001)**：解密操作失败
- **FPE_ENCRYPTION_ERROR (6000)**：FPE加密失败
- **FPE_DECRYPTION_ERROR (6001)**：FPE解密失败

## 安全最佳实践

1. **密钥保护**：
   - 密钥库密码和根密钥密码应存储在安全的地方，避免硬编码
   - 定期轮换密钥，特别是根密钥

2. **加密算法选择**：
   - 使用AES-256进行对称加密
   - 使用RSA-2048或更高版本进行非对称加密
   - 使用SHA-256或更高版本进行哈希计算

3. **安全编码**：
   - 避免在日志中记录敏感信息
   - 验证所有输入参数
   - 使用安全的随机数生成器

4. **资源管理**：
   - 使用完毕后关闭SDK
   - 及时清除敏感数据的内存

## 配置说明

### JVM参数

如果使用AES-256算法，需要安装Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files。

## 版本历史

- **1.0.1-SNAPSHOT**：初始版本，包含基本功能

## 许可证

采用 MIT License许可证。

## 联系方式

如有问题或建议，请联系：

- 邮箱：13439298452@163.com
