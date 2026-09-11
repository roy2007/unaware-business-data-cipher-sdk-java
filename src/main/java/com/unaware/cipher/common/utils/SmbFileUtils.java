package com.unaware.cipher.common.utils;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;

/**
 * @author: Roy rui wang
 * @data 2026年01月12日 14:14
 */
public class SmbFileUtils {
    private static final int BUFFER_SIZE = 4096;

    public static final long MAX_FILE_SIZE = 100L * 1024 * 1024; // 100 MB
    /**
     * 创建 NtlmPasswordAuthentication 对象（用于 JCIFS 认证）
     * 注意：JCIFS 的 URL 必须是合法格式，密码需 URL 编码
     */
    private static NtlmPasswordAuthentication createAuth(String smbUrl) throws MalformedURLException {
        // JCIFS 会自动从 URL 中提取用户/密码，但前提是 URL 合法
        // 所以我们直接使用 SmbFile 构造函数即可，无需手动解析
        // 此方法保留以备扩展（如显式传入凭据）
        return null; // 实际认证由 URL 自带
    }

    /**
     * 生成 SMB 文件的 SHA-256 校验和
     */
    public static String generateSHA256Checksum(String smbUrl, String version, String versionName) throws IOException, NoSuchAlgorithmException {
        try {
            SmbFile smbFile = new SmbFile(smbUrl);
            if (!smbFile.exists()) {
                throw new IOException("File not found on SMB share: " + smbUrl);
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 1. 流式读取文件并更新摘要
            if (!smbFile.isFile()) {
                throw new IllegalArgumentException("路径不是文件: " + smbUrl);
            }

            long fileSize = smbFile.length(); // 获取文件大小（字节）

            if (fileSize >= MAX_FILE_SIZE) {
                throw new IllegalArgumentException(String.format("文件大小 %.2f MB >= 100 MB，拒绝加载", fileSize / (1024.0 * 1024)));
            }

            // 读取全部内容
            try (InputStream in = smbFile.getInputStream(); ByteArrayOutputStream buffer = new ByteArrayOutputStream((int) fileSize)) {

                byte[] readBuf = new byte[BUFFER_SIZE];
                int n;
                while ((n = in.read(readBuf)) != -1) {
                    buffer.write(readBuf, 0, n);
                }
                return KeystorePathUtils.combinedByte(buffer.toByteArray(), version, versionName);
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid SMB URL: " + smbUrl, e);
        }
    }

    /**
     * 验证 SMB 文件的 SHA-256 校验和
     */
    public static boolean verifySHA256Checksum(String smbUrl, String expectedChecksum,String version, String versionName) throws IOException, NoSuchAlgorithmException {
        String actualChecksum = generateSHA256Checksum(smbUrl, version, versionName);
        return actualChecksum.equals(expectedChecksum);
    }

    /**
     * 将校验和保存为 .chksum 文件（写入 SMB）
     */
    public static void saveChecksumToFile(String smbUrl, String checksum) throws IOException {
        String chkSumUrl = smbUrl + ".chksum";
        try {
            SmbFile smbFile = new SmbFile(chkSumUrl);
            try (OutputStream os = smbFile.getOutputStream()) {
                os.write((checksum + "\n").getBytes(StandardCharsets.UTF_8));
            }
            return;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid SMB URL: " + chkSumUrl, e);
        }
    }

    /**
     * 从 SMB 读取 .chksum 文件内容
     */
    public static String readChecksumFromFile(String smbChecksumUrl) throws IOException {
        try {
            SmbFile smbFile = new SmbFile(smbChecksumUrl);
            if (!smbFile.exists()) {
                throw new IOException("Checksum file not found: " + smbChecksumUrl);
            }

            try (InputStream is = smbFile.getInputStream()) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[256]; // Base64 SHA-256 长度为 44
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toString("UTF-8").trim();
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid SMB URL: " + smbChecksumUrl, e);
        }
    }

    /**
     * 在 SMB 共享上创建按日期命名的文件夹（yyyyMMdd）
     * 示例输入: smb://user:pass@host/share/basePath/
     */
    public static String createDateFolder(String smbBasePath) throws IOException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
        String dateStr = sdf.format(new java.util.Date());

        // 确保 basePath 以 / 结尾
        String normalizedBase = smbBasePath.endsWith("/") ? smbBasePath : smbBasePath + "/";
        String newFolderPath = normalizedBase + dateStr;

        try {
            SmbFile folder = new SmbFile(newFolderPath);
            if (!folder.exists()) {
                folder.mkdirs(); // JCIFS 的 mkdirs 会递归创建目录
            }
            return newFolderPath;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid SMB base path: " + smbBasePath, e);
        }
    }

    public static boolean smbFileExists(String smbUrl) throws IOException {
        try {
            return new SmbFile(smbUrl).exists();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid SMB URL: " + smbUrl, e);
        }
    }
}
