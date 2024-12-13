package com.inmaytide.orbit.authorization.configuration;

public enum ErrorCode implements com.inmaytide.exception.web.domain.ErrorCode {

    E_0x02100001("0x02100001", "系统中不存在ID/登录名/手机号码/邮箱地址/员工编号为 {0} 的用户信息"),
    E_0x02100002("0x02100002", "用户所属租户不存在"),
    E_0x02100003("0x02100003", "用户所属租户已禁用"),
    E_0x02100004("0x02100004", "用户所属租户授权已过期"),
    E_0x02100005("0x02100005", "用户已在其他位置登录"),
    E_0x02100006("0x02100006", "用户密码输入错误"),
    E_0x02100007("0x02100007", "用户名或密码输入错误"),

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
