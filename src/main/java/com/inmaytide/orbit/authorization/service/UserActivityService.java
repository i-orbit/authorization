package com.inmaytide.orbit.authorization.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
public interface UserActivityService {

    void cacheUserActivity(HttpServletRequest request, OAuth2TokenIntrospection tokenClaims);

    /**
     * 获取指定租户当前在线用户数
     *
     * @param tenant 指定租户ID
     * @return 租户当前在线用户数量
     */
    Long getNumberOfOnlineUsers(String tenant);

}
