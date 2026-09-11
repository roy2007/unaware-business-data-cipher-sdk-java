package com.unaware.cipher.exception;

/**
 * 加密SDK错误码枚举类
 * @author Roy rui wang
 * @version 1.0
 * @since 2024年12月15日 17:08
 */
public enum ErrorCode {
    // 通用错误 (1000-1999)
    SUCCESS("0000", "成功"),
    UNKNOWN_ERROR("1000", "未知错误"),
    PARAMETER_ERROR("1001", "参数错误"),
    NULL_POINTER_ERROR("1002", "空指针异常"),
    ILLEGAL_STATE_ERROR("1003", "非法状态异常"),
    IO_ERROR("1004", "IO操作异常"),
    
    // 密钥库错误 (2000-2999)
    KEY_STORE_CREATE_ERROR("2000", "密钥库创建失败"),
    KEY_STORE_LOAD_ERROR("2001", "密钥库加载失败"),
    KEY_STORE_SAVE_ERROR("2002", "密钥库保存失败"),
    KEY_STORE_NOT_FOUND("2003", "密钥库文件未找到"),
    KEY_STORE_PASSWORD_ERROR("2004", "密钥库密码错误"),
    KEY_STORE_ENTRY_NOT_FOUND("2005", "密钥库条目未找到"),
    KEY_STORE_ENTRY_EXISTS("2006", "密钥库条目已存在"),
    KEY_STORE_MAX_LIMIT_EXCEEDED("2007", "密钥库条目数量达到上限"),
    
    // 密钥管理错误 (3000-3999)
    KEY_GENERATION_ERROR("3000", "密钥生成失败"),
    KEY_DERIVATION_ERROR("3001", "密钥派生失败"),
    KEY_INVALID_ERROR("3002", "无效密钥"),
    KEY_LENGTH_ERROR("3003", "密钥长度错误"),
    KEY_PASSWORD_ERROR("3004", "密钥密码错误"),
    ROOT_KEY_NOT_FOUND("3005", "根密钥未找到"),
    ROOT_KEY_CREATE_ERROR("3006", "根密钥创建失败"),
    SECRET_KEY_TO_STRING_ERROR("3007", "密钥转换为字符串失败"),
    SECRET_KEY_FROM_STRING_ERROR("3008", "字符串转换为密钥失败"),


    // 加密算法错误 (4000-4999)
    ENCRYPTION_ERROR("4000", "加密失败"),
    DECRYPTION_ERROR("4001", "解密失败"),
    ALGORITHM_NOT_SUPPORTED("4002", "算法不支持"),
    INVALID_ALGORITHM_PARAMETER("4003", "无效算法参数"),
    
    // 哈希和HMAC错误 (5000-5999)
    HASH_ERROR("5000", "哈希计算失败"),
    HMAC_ERROR("5001", "HMAC计算失败"),
    
    // RSA相关错误 (6000-6999)
    RSA_KEY_PAIR_GENERATION_ERROR("6000", "RSA密钥对生成失败"),
    RSA_SIGN_ERROR("6001", "RSA签名生成失败"),
    RSA_VERIFY_ERROR("6002", "RSA签名验证失败"),
    
    // FPE相关错误 (7000-7999)
    FPE_ENCRYPTION_ERROR("7000", "FPE加密失败"),
    FPE_DECRYPTION_ERROR("7001", "FPE解密失败"),
    FPE_CHARSET_ERROR("7002", "FPE字符集错误"),
    FPE_TWEAK_ERROR("7003", "FPE调整值错误"),
    
    // 缓存相关错误 (8000-8999)
    CACHE_INIT_ERROR("8000", "缓存初始化失败"),
    CACHE_OPERATION_ERROR("8001", "缓存操作失败"),
    
    // 证书相关错误 (9000-9999)
    CERTIFICATE_LOAD_ERROR("9000", "证书加载失败"),
    CERTIFICATE_PARSE_ERROR("9001", "证书解析失败"),
    CERTIFICATE_VALIDATION_ERROR("9002", "证书验证失败"),
    CERTIFICATE_NOT_FOUND("9003", "证书未找到"),
    INVALID_SECRET_KEY_STRING("9004", "无效的密钥字符串");

    private final String code;
    private final String description;

    /**
     * 构造函数
     *
     * @param code        错误码
     * @param description 错误描述
     */
    ErrorCode(String code, String description) {
        this.code = code;
        this.description = description;
    }

    /**
     * 获取错误码
     *
     * @return 错误码
     */
    public String getCode() {
        return code;
    }

    /**
     * 获取错误描述
     *
     * @return 错误描述
     */
    public String getDescription() {
        return description;
    }

    /**
     * 根据错误码获取错误枚举
     *
     * @param code 错误码
     * @return 错误枚举
     */
    public static ErrorCode fromCode(String code) {
        for (ErrorCode errorCode : values()) {
            if (errorCode.getCode().equals(code)) {
                return errorCode;
            }
        }
        return UNKNOWN_ERROR;
    }

    @Override
    public String toString() {
        return code + ": " + description;
    }
}
