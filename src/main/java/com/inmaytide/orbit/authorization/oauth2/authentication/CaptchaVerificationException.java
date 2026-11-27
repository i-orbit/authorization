package com.inmaytide.orbit.authorization.oauth2.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * 滑块验证码校验失败。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
public class CaptchaVerificationException extends AuthenticationException {

    public CaptchaVerificationException(String message) {
        super(message);
    }
}
