package com.inmaytide.orbit.authorization.configuration;

public enum ErrorCode implements com.inmaytide.exception.web.domain.ErrorCode {

    E_0x02100001("0x02100001", "系统中不存在登录名/手机号码/邮箱地址为 {0} 的用户信息"),
    E_0x02100002("0x02100002", "用户所属租户不存在"),
    E_0x02100003("0x02100003", "用户所属租户已禁用"),
    E_0x02100004("0x02100004", "用户所属租户授权已过期"),

    ;

    private final String value;

    private final String description;

    ErrorCode(String value, String description) {
        this.value = value;
        this.description = description;
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public String description() {
        return this.description;
    }
}
