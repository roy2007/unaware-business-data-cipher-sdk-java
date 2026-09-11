package com.unaware.cipher.exception;

/**
 * 加密SDK基础异常类
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 *
 */
public class EncryptionException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * 构造函数
     *
     * @param errorCode 错误码
     * @param message   错误消息
     */
    public EncryptionException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * 构造函数
     *
     * @param errorCode 错误码
     * @param message   错误消息
     * @param cause     异常原因
     */
    public EncryptionException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * 获取错误码
     *
     * @return 错误码
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * 获取错误码字符串表示
     *
     * @return 错误码字符串
     */
    public String getErrorCodeString() {
        return errorCode.getCode();
    }
}
