package com.inmaytide.orbit.authorization.domain;

import lombok.Data;

/**
 * 滑块拼图验证码挑战。
 *
 * @author inmaytide
 * @since 2026/11/27
 */
@Data
public class CaptchaChallenge {

    /**
     * 挑战 ID，提交登录时随验证码位置一起回传。
     */
    private String id;

    /**
     * 背景图，data:image/png;base64 格式。
     */
    private String background;

    /**
     * 拼图块，data:image/png;base64 格式。
     */
    private String piece;

    private int width;

    private int height;

    private int pieceWidth;

    private int pieceHeight;

    /**
     * 拼图块的 Y 坐标（与背景图同一坐标系）。
     */
    private int pieceY;

    /**
     * 允许的像素误差。
     */
    private int tolerance;

    private long expiresIn;
}
