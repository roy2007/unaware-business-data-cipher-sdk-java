package com.unaware.cipher.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 */
public class SelfSignedCertificateUtil {
    private static final Logger logger = LoggerFactory.getLogger(SelfSignedCertificateUtil.class);

    // 在 addExtension 之后添加
    private final static GeneralName[] subjectAltNames = {
            new GeneralName(GeneralName.dNSName, "localhost"),
            new GeneralName(GeneralName.dNSName, "127.0.0.1"),
            new GeneralName(GeneralName.iPAddress, "127.0.0.1")
    };

    /**
     * 创建自签名 X.509 证书
     *
     * @param keyPair      公私钥对（支持 RSA / EC）
     * @param subject      证书主题（如 "CN=localhost, O=MyCompany, C=CN"）
     * @param validityDays 有效期（天），建议 ≤ 825（Chrome 限制）
     * @return X509Certificate
     */
    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair, String subject,
                                                              int validityDays, boolean setExtension) throws Exception {

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 1. 构建证书主题和颁发者（自签名为同一实体）
        X500Name subjectDN = new X500Name(subject);
        X500Name issuerDN = subjectDN; // 自签名

        // 2. 生成唯一序列号
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // 3. 设置有效期
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus(validityDays, ChronoUnit.DAYS));

        // 4. 初始化证书构建器
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerDN,
                serialNumber,
                notBefore,
                notAfter,
                subjectDN,
                publicKey
        );

        // 5. 添加关键扩展（可选但推荐）CA: false → 设为 true 表示是 CA
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature |
                        KeyUsage.keyEncipherment |
                        KeyUsage.dataEncipherment
        ));
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_clientAuth
        }));
        if (setExtension) {
            certBuilder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(subjectAltNames));
        }

        // 6. 确定签名算法
        String signatureAlgorithm = getSignatureAlgorithm(keyPair);

        // 7. 创建签名器
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .build(privateKey);

        // 8. 生成证书
        return new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * 根据密钥类型自动选择签名算法
     */
    private static String getSignatureAlgorithm(KeyPair keyPair) {
        String algorithm = keyPair.getPublic().getAlgorithm();
        switch (algorithm.toUpperCase()) {
            case "RSA":
                return "SHA256WithRSA";
            case "EC":
                return "SHA256withECDSA";
            case "DSA":
                return "SHA256withDSA";
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        }
    }

    // ================== 使用示例 ==================
    public static void main(String[] args) throws Exception {
        // 1. 生成密钥对（以 RSA 为例）
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // 2. 创建自签名证书
        String subject = "CN=localhost, O=yunwuye, L=Beijing, C=CN";
        X509Certificate cert = createSelfSignedCertificate(keyPair, subject, 365, true);

        // 3. 验证证书
        logger.debug("Subject: {}", cert.getSubjectDN());
        logger.debug("Issuer:: {}", cert.getIssuerDN());
        logger.debug("Serial: : {}", cert.getSerialNumber());
        logger.debug("Valid from: : {}", cert.getNotBefore());
        logger.debug("Valid to: : {}", cert.getNotAfter());
        logger.debug("Signature Algorithm: : {}", cert.getSigAlgName());

        // 4. （可选）保存为 PEM 文件
        saveAsPem(cert, keyPair.getPrivate(), "selfsigned.pem");
    }

    /**
     * 保存证书 + 私钥为 PEM 格式（便于 OpenSSL 使用）
     */
    public static void saveAsPem(X509Certificate cert, java.security.PrivateKey privateKey, String filename) throws Exception {
        try (FileOutputStream fos = new java.io.FileOutputStream(filename);
             OutputStreamWriter writer = new java.io.OutputStreamWriter(fos)) {

            // 写入私钥（PKCS#8 格式）
            String privPem = "-----BEGIN PRIVATE KEY-----\n" +
                    java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                            .encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----\n";
            writer.write(privPem);

            // 写入证书
            String certPem = "-----BEGIN CERTIFICATE-----\n" +
                    java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                            .encodeToString(cert.getEncoded()) +
                    "\n-----END CERTIFICATE-----\n";
            writer.write(certPem);
        }
        logger.debug("PEM file saved: : {}", filename);
    }
}
