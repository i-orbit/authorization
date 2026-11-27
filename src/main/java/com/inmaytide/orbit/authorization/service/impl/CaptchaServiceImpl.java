package com.inmaytide.orbit.authorization.service.impl;

import com.inmaytide.orbit.authorization.domain.CaptchaChallenge;
import com.inmaytide.orbit.authorization.service.CaptchaService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.imageio.ImageIO;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

/**
 * 基于随机噪点背景的滑块拼图验证码。
 *
 * <p>服务端随机生成缺口位置并写入 Redis（一次性、短有效期），前端只拿到背景图和拼图块，
 * 无法从响应中直接读出正确位置。</p>
 *
 * @author inmaytide
 * @since 2026/11/27
 */
@Slf4j
@Service
public class CaptchaServiceImpl implements CaptchaService {

    private static final String REDIS_KEY_PREFIX = "orbit:captcha:";

    private static final Duration TTL = Duration.ofMinutes(2);

    private static final int WIDTH = 320;

    private static final int HEIGHT = 160;

    private static final int PIECE_SIZE = 52;

    private static final int TOLERANCE = 6;

    private static final int MIN_TARGET_X = 60;

    private static final int TARGET_X_MARGIN = 20;

    private static final int TARGET_Y_MARGIN = 12;

    private static final String DATA_URL_PREFIX = "data:image/png;base64,";

    private final StringRedisTemplate redisTemplate;

    private final SecureRandom random = new SecureRandom();

    public CaptchaServiceImpl(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public CaptchaChallenge createChallenge() {
        String id = UUID.randomUUID().toString().replace("-", "");
        int maxTargetX = WIDTH - PIECE_SIZE - TARGET_X_MARGIN;
        int targetX = MIN_TARGET_X + random.nextInt(Math.max(1, maxTargetX - MIN_TARGET_X));
        int targetY = TARGET_Y_MARGIN + random.nextInt(Math.max(1, HEIGHT - PIECE_SIZE - TARGET_Y_MARGIN * 2));

        BufferedImage background = drawBackground();
        BufferedImage piece = cropPiece(background, targetX, targetY);
        drawGap(background, targetX, targetY);

        redisTemplate.opsForValue().set(REDIS_KEY_PREFIX + id, Integer.toString(targetX), TTL);

        CaptchaChallenge challenge = new CaptchaChallenge();
        challenge.setId(id);
        challenge.setBackground(toDataUrl(background));
        challenge.setPiece(toDataUrl(piece));
        challenge.setWidth(WIDTH);
        challenge.setHeight(HEIGHT);
        challenge.setPieceWidth(PIECE_SIZE);
        challenge.setPieceHeight(PIECE_SIZE);
        challenge.setPieceY(targetY);
        challenge.setTolerance(TOLERANCE);
        challenge.setExpiresIn(TTL.toSeconds());
        return challenge;
    }

    @Override
    public boolean verify(String id, Integer x) {
        if (!StringUtils.hasText(id) || x == null) {
            log.debug("【验证码-校验】缺少验证码参数");
            return false;
        }
        String key = REDIS_KEY_PREFIX + id;
        String target = redisTemplate.opsForValue().get(key);
        // 一次性使用：无论成功失败都删除，防止同一挑战被重复尝试
        redisTemplate.delete(key);
        if (!StringUtils.hasText(target)) {
            log.debug("【验证码-校验】验证码不存在或已过期, {captchaId: {}}", id);
            return false;
        }
        try {
            int offset = Math.abs(x - Integer.parseInt(target));
            boolean passed = offset <= TOLERANCE;
            if (!passed) {
                log.debug("【验证码-校验】位置偏差过大, {captchaId: {}, offset: {}}", id, offset);
            }
            return passed;
        } catch (NumberFormatException e) {
            log.warn("【验证码-校验】验证码数据格式错误, {captchaId: {}}", id);
            return false;
        }
    }

    private BufferedImage drawBackground() {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = image.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        graphics.setPaint(new GradientPaint(0, 0, randomColor(), WIDTH, HEIGHT, randomColor()));
        graphics.fillRect(0, 0, WIDTH, HEIGHT);

        for (int i = 0; i < 12; i++) {
            graphics.setColor(new Color(random.nextInt(256), random.nextInt(256), random.nextInt(256), 40));
            graphics.fillOval(random.nextInt(WIDTH), random.nextInt(HEIGHT),
                    20 + random.nextInt(80), 20 + random.nextInt(80));
        }

        for (int i = 0; i < 8; i++) {
            graphics.setColor(new Color(255, 255, 255, 50 + random.nextInt(80)));
            graphics.setStroke(new BasicStroke(1 + random.nextFloat() * 2));
            graphics.drawLine(random.nextInt(WIDTH), random.nextInt(HEIGHT),
                    random.nextInt(WIDTH), random.nextInt(HEIGHT));
        }

        for (int i = 0; i < 120; i++) {
            image.setRGB(random.nextInt(WIDTH), random.nextInt(HEIGHT), random.nextInt(0x1000000));
        }
        graphics.dispose();
        return image;
    }

    private BufferedImage cropPiece(BufferedImage background, int targetX, int targetY) {
        BufferedImage piece = new BufferedImage(PIECE_SIZE, PIECE_SIZE, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = piece.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        graphics.drawImage(background.getSubimage(targetX, targetY, PIECE_SIZE, PIECE_SIZE), 0, 0, null);
        graphics.setColor(new Color(255, 255, 255, 180));
        graphics.setStroke(new BasicStroke(1.5f));
        graphics.drawRoundRect(0, 0, PIECE_SIZE - 1, PIECE_SIZE - 1, 8, 8);
        graphics.dispose();
        return piece;
    }

    private void drawGap(BufferedImage background, int targetX, int targetY) {
        Graphics2D graphics = background.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        graphics.setColor(new Color(0, 0, 0, 150));
        graphics.fillRoundRect(targetX, targetY, PIECE_SIZE, PIECE_SIZE, 8, 8);
        graphics.setColor(new Color(255, 255, 255, 130));
        graphics.setStroke(new BasicStroke(1.5f));
        graphics.drawRoundRect(targetX, targetY, PIECE_SIZE, PIECE_SIZE, 8, 8);
        graphics.dispose();
    }

    private Color randomColor() {
        return new Color(60 + random.nextInt(140), 60 + random.nextInt(140), 60 + random.nextInt(140));
    }

    private String toDataUrl(BufferedImage image) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            ImageIO.write(image, "png", output);
            return DATA_URL_PREFIX + Base64.getEncoder().encodeToString(output.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to render captcha image", e);
        }
    }
}
