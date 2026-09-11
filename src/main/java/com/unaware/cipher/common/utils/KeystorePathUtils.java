package com.unaware.cipher.common.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 文件处理工具类
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年05月03日
 */
public class KeystorePathUtils {
    private static final String SMB_PREFIX = "smb://";

    /**
     * 生成文件的SHA-256校验和
     *
     * @param filePath 文件路径
     * @return SHA-256校验和（Base64编码）
     * @throws IOException              IO异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public static String generateSHA256Checksum(String filePath, String version, String versionName) throws IOException, NoSuchAlgorithmException {
        if (filePath.startsWith(SMB_PREFIX)) {
            return SmbFileUtils.generateSHA256Checksum(filePath, version, versionName);
        }

        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("File not found: " + filePath);
        }
        byte[] allBytes = Files.readAllBytes(file.toPath());
        return combinedByte(allBytes, version, versionName);
    }

    public static String combinedByte(byte[] fileBytes, String version, String versionName) {
        // 2. 拼接附加信息（避免直接字符串拼接，防止编码问题）
        String suffix = "\nVERSION:" + version + "\nVERSION_NAME:" + versionName + "\n";
        byte[] suffixBytes = suffix.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // 3. 合并字节数组
        byte[] combined = new byte[fileBytes.length + suffixBytes.length];
        System.arraycopy(fileBytes, 0, combined, 0, fileBytes.length);
        System.arraycopy(suffixBytes, 0, combined, fileBytes.length, suffixBytes.length);

        // 4. 计算 SHA-256
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined);
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("计算校验和失败", e);
        }
    }

    /**
     * 验证文件的SHA-256校验和
     *
     * @param filePath         文件路径
     * @param expectedChecksum 预期的SHA-256校验和（Base64编码）
     * @return 是否匹配
     * @throws IOException              IO异常
     * @throws NoSuchAlgorithmException 算法不支持异常
     */
    public static boolean verifySHA256Checksum(String filePath, String expectedChecksum, String version, String versionName) throws IOException, NoSuchAlgorithmException {
        if (filePath.startsWith(SMB_PREFIX)) {
            return SmbFileUtils.verifySHA256Checksum(filePath, expectedChecksum, version, versionName);
        }

        String actualChecksum = generateSHA256Checksum(filePath, version, versionName);
        return actualChecksum.equals(expectedChecksum);
    }

    /**
     * 保存SHA-256校验和到文件
     *
     * @param filePath 源文件路径
     * @param checksum SHA-256校验和（Base64编码）
     * @throws IOException IO异常
     */
    public static void saveChecksumToFile(String filePath, String checksum) throws IOException {
        if (filePath.startsWith(SMB_PREFIX)) {
             SmbFileUtils.saveChecksumToFile(filePath, checksum);
            return;
        }

        String checksumFilePath = filePath + ".chksum";
        java.io.FileWriter writer = new java.io.FileWriter(checksumFilePath);
        writer.write(checksum);
        writer.close();
    }

    /**
     * 从文件读取SHA-256校验和
     *
     * @param checksumFilePath 校验和文件路径
     * @return SHA-256校验和（Base64编码）
     * @throws IOException IO异常
     */
    public static String readChecksumFromFile(String checksumFilePath) throws IOException {
        if (checksumFilePath.startsWith(SMB_PREFIX)) {
            return SmbFileUtils.readChecksumFromFile(checksumFilePath);
        }

        File file = new File(checksumFilePath);
        if (!file.exists()) {
            throw new IOException("Checksum file not found: " + checksumFilePath);
        }

        java.io.FileReader reader = new java.io.FileReader(file);
        char[] buffer = new char[256]; // SHA-256的Base64编码长度为44
        int bytesRead = reader.read(buffer);
        reader.close();
        return new String(buffer, 0, bytesRead).trim();
    }

    /**
     * 创建按年月日（天）生成的唯一文件夹
     *
     * @param basePath 基础路径
     * @return 创建的文件夹路径
     */
    public static String createDateFolder(String basePath) throws IOException {
        if (basePath.startsWith(SMB_PREFIX)) {
            return SmbFileUtils.createDateFolder(basePath);
        }

        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyyMMdd");
        String dateStr = sdf.format(new java.util.Date());
        String folderPath = basePath + File.separator + dateStr;
        File folder = new File(folderPath);
        if (!folder.exists() && !folder.mkdirs()) {
            throw new RuntimeException("无法创建目录: " + folder.getAbsolutePath());
        }
        return folderPath;
    }

    public static boolean checkFileExists(String keystorePath) throws IOException {
        if (keystorePath == null || keystorePath.contains("..")) {
            throw new RuntimeException("无效的路径");
        }
        if (keystorePath.startsWith(SMB_PREFIX)) {
            return SmbFileUtils.smbFileExists(keystorePath);
        }
        return (new File(keystorePath).exists());
    }

    /**
     * 查找密钥库文件路径
     *
     * @param keystoreFileName 密钥库文件名
     * @return 密钥库文件路径
     * @throws Exception 可能的异常
     */
    public static String findKeystoreFilePath(String keystoreFileName, String keystorePathDir) throws Exception {
        int idx = keystoreFileName.indexOf('_');
        if (idx != -1 && idx + 9 < keystoreFileName.length()) {
            String dateStr = keystoreFileName.substring(idx + 1, idx + 9);
            if (dateStr.length() == 8) {
                String pathSeparator = File.separator;
                if (keystorePathDir.startsWith(SMB_PREFIX)) {
                    pathSeparator = "/";
                }
                if (!keystorePathDir.endsWith(pathSeparator)) {
                    keystorePathDir += pathSeparator;
                }
                String dateFolder = keystorePathDir + dateStr;
                String keystoreFilePath = dateFolder + pathSeparator + keystoreFileName;
                if (checkFileExists(keystoreFilePath)) {
                    return keystoreFilePath;
                }
            }
        }

        throw new Exception("密钥库文件未找到：" + keystoreFileName);
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String getOsKeystorePath(String winTestKeystorePath, String linuxTestKeystorePath) {
        String osName = System.getProperty("os.name");
        if (osName == null) {
            return linuxTestKeystorePath;
        }

        String lowerOsName = osName.toLowerCase();
        if (lowerOsName.contains("win")) {
            return winTestKeystorePath;
        } else if (lowerOsName.contains("mac")) {
            // 假设 Mac 与 Linux 相同
            return linuxTestKeystorePath;
        } else {
            return linuxTestKeystorePath;
        }
    }
}
