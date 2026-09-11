package com.unaware.cipher.common.utils;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/**
 * @author: Roy rui wang
 * @data 2026年01月08日 16:28
 */
public class CrossPlatformFileUtil {

    /**
     * 写入文本文件（UTF-8）
     */
    public static void writeTextFile(String basePath, String relativePath, String content) throws IOException {
        Path fullPath = Paths.get(basePath, relativePath).normalize();
        // 创建父目录
        Files.createDirectories(fullPath.getParent());
        Files.write(fullPath, content.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 读取文本文件（UTF-8）
     */
    public static String readTextFile(String basePath, String relativePath) throws IOException {
        Path fullPath = Paths.get(basePath, relativePath).normalize();
        if (!Files.exists(fullPath)) {
            throw new FileNotFoundException("File not found: " + fullPath);
        }
        return new String(Files.readAllBytes(fullPath), StandardCharsets.UTF_8);
    }

    /**
     * 写入二进制文件（如 .jks, .p12, 图片等）
     */
    public static void writeBinaryFile(String basePath, String relativePath, byte[] data) throws IOException {
        Path fullPath = Paths.get(basePath, relativePath).normalize();
        Files.createDirectories(fullPath.getParent());
        Files.write(fullPath, data);
    }

    /**
     * 读取二进制文件
     */
    public static byte[] readBinaryFile(String basePath, String relativePath) throws IOException {
        Path fullPath = Paths.get(basePath, relativePath).normalize();
        if (!Files.exists(fullPath)) {
            throw new FileNotFoundException("File not found: " + fullPath);
        }
        return Files.readAllBytes(fullPath);
    }

    /**
     * 安全拼接路径（防止路径穿越）
     */
    public static Path safeResolve(String baseDir, String userPath) {
        Path base = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolved = base.resolve(userPath).normalize();

        // 防止路径穿越攻击（如 ../../etc/passwd）
        if (!resolved.startsWith(base)) {
            throw new SecurityException("Access denied: " + userPath);
        }
        return resolved;
    }
}
