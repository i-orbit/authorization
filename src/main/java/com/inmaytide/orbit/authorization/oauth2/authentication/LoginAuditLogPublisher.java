package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.core.domain.AuthenticatedUser;
import com.inmaytide.orbit.framework.core.producer.KafkaProducer;
import com.inmaytide.orbit.framework.log.Constants;
import com.inmaytide.orbit.framework.log.OperationResult;
import com.inmaytide.orbit.framework.log.OperationType;
import com.inmaytide.orbit.framework.log.domain.OperationLogBuilder;
import com.inmaytide.orbit.framework.log.domain.OperationLogDTO;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID;

/**
 * Publishes successful and failed login attempts using the standard operation log format.
 *
 * @author inmaytide
 * @since 2026/11/23
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class LoginAuditLogPublisher {

    static final String RESOURCE_TYPE = "User";

    private static final String OPERATION_SUCCESS = "用户登录成功";

    private static final String OPERATION_FAILURE = "用户登录失败";

    private final KafkaProducer kafkaProducer;

    private final UserService userService;

    private final ObjectMapper objectMapper;

    public void success(HttpServletRequest request, Authentication authentication) {
        try {
            publish(buildSuccessLog(request, authentication));
        } catch (RuntimeException e) {
            log.error("Failed to prepare successful login audit log", e);
        }
    }

    public void failure(HttpServletRequest request, SecurityErrorCode errorCode) {
        try {
            publish(buildFailureLog(request, errorCode));
        } catch (RuntimeException e) {
            log.error("Failed to prepare failed login audit log", e);
        }
    }

    OperationLogDTO buildSuccessLog(HttpServletRequest request, Authentication authentication) {
        String userId = authentication.getPrincipal() == null
                ? null
                : authentication.getPrincipal().toString();
        String tenantId = getAdditionalParameter(authentication, PARAMETER_NAME_TENANT_ID);

        AuthenticatedUser user = null;
        if (StringUtils.isNotBlank(userId)) {
            user = new AuthenticatedUser();
            user.setId(userId);
            user.setTenantId(tenantId);
        }

        return buildLog(request, user, userId, OperationResult.SUCCESS, OPERATION_SUCCESS, null);
    }

    OperationLogDTO buildFailureLog(HttpServletRequest request, SecurityErrorCode errorCode) {
        AttemptedUser attemptedUser = findAttemptedUser(request);
        String errorDescription = errorCode.getCode() + ", " + errorCode.getDescription();
        return buildLog(
                request,
                attemptedUser.authenticatedUser(),
                attemptedUser.userId(),
                OperationResult.FAILURE,
                OPERATION_FAILURE,
                errorDescription
        );
    }

    private OperationLogDTO buildLog(HttpServletRequest request,
                                     AuthenticatedUser user,
                                     String resourceId,
                                     OperationResult result,
                                     String operation,
                                     String errorDescription) {
        return OperationLogBuilder.startAt(resolveStartAt(request))
                .httpServletRequest(request)
                .authenticatedUser(user)
                .operationType(OperationType.OTHER)
                .operation(operation)
                .resourceType(RESOURCE_TYPE)
                .resourceId(resourceId)
                .requestBody(sanitizedLoginRequest(request))
                .operateResult(result)
                .errorDescription(errorDescription)
                .build();
    }

    private AttemptedUser findAttemptedUser(HttpServletRequest request) {
        Object value = request.getAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_USERNAME_ATTRIBUTE);
        if (!(value instanceof String username) || StringUtils.isBlank(username)) {
            return AttemptedUser.EMPTY;
        }
        try {
            Optional<User> found = userService.getByUsername(username);
            if (found.isEmpty()) {
                return AttemptedUser.EMPTY;
            }
            User user = found.get();
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setId(user.getId());
            authenticatedUser.setTenantId(user.getTenantId());
            return new AttemptedUser(authenticatedUser, user.getId());
        } catch (RuntimeException e) {
            log.warn("Failed to resolve user for failed login audit, username: {}", username, e);
            return AttemptedUser.EMPTY;
        }
    }

    private Map<String, Object> sanitizedLoginRequest(HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        putIfPresent(body, "username",
                request.getAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_USERNAME_ATTRIBUTE));
        putIfPresent(body, "platform",
                request.getAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_PLATFORM_ATTRIBUTE));
        putIfPresent(body, "forcedReplacement",
                request.getAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_FORCED_REPLACEMENT_ATTRIBUTE));
        return body;
    }

    private long resolveStartAt(HttpServletRequest request) {
        Object value = request.getAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_STARTED_AT_ATTRIBUTE);
        return value instanceof Long startedAt ? startedAt : System.currentTimeMillis();
    }

    private String getAdditionalParameter(Authentication authentication, String name) {
        if (!(authentication instanceof UsernamePasswordAuthenticationToken token)) {
            return null;
        }
        Map<String, Object> parameters = token.getAdditionalParameters();
        if (parameters == null || parameters.get(name) == null) {
            return null;
        }
        return parameters.get(name).toString();
    }

    private void publish(OperationLogDTO operationLog) {
        try {
            String message = objectMapper.writeValueAsString(operationLog);
            Thread.ofVirtual().start(() -> kafkaProducer
                    .send(Constants.KAFKA_TOPIC_OPERATION_LOG, message)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish login audit log", ex);
                        }
                    }));
        } catch (RuntimeException e) {
            log.error("Failed to prepare login audit log", e);
        }
    }

    private static void putIfPresent(Map<String, Object> target, String name, Object value) {
        if (value != null) {
            target.put(name, value);
        }
    }

    private record AttemptedUser(AuthenticatedUser authenticatedUser, String userId) {

        private static final AttemptedUser EMPTY = new AttemptedUser(null, null);

    }

}
