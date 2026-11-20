package com.inmaytide.orbit.authorization.domain;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.inmaytide.orbit.framework.Version;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import com.inmaytide.orbit.framework.core.utils.ApplicationContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.MediaType;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serializable;

/**
 * @author inmaytide
 * @since 2026/11/20
 */
@Data
public class LoginRequest implements Serializable {

    private final static long serialVersionUid = Version.SERIAL_VERSION_UID;

    private String username;

    private String password;

    private ClientPlatform platform;

    @JsonAlias({"forcedReplacement", "forceReplacemnt"})
    private boolean forceReplacement = false;

    public static LoginRequest withHttpServletRequest(HttpServletRequest request) {
        try {
            if (request.getContentType() != null && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
                return ApplicationContextHolder.getBean(ObjectMapper.class)
                        .readValue(request.getInputStream(), LoginRequest.class);
            }
            LoginRequest inst = new LoginRequest();
            inst.setUsername(request.getParameter("username"));
            inst.setPassword(request.getParameter("password"));
            String platform = request.getParameter("platform");
            if (StringUtils.isNotBlank(platform)) {
                inst.setPlatform(ClientPlatform.valueOf(platform));
            }
            String forceReplacement = StringUtils.firstNonBlank(
                    request.getParameter("forceReplacement"),
                    request.getParameter("forcedReplacement"),
                    request.getParameter("forceReplacemnt")
            );
            inst.setForceReplacement(isTrue(forceReplacement));
            return inst;
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to parse login request", e);
        }
    }

    private static boolean isTrue(String value) {
        return "true".equalsIgnoreCase(value) || "1".equals(value)
                || "yes".equalsIgnoreCase(value) || "y".equalsIgnoreCase(value);
    }

}
