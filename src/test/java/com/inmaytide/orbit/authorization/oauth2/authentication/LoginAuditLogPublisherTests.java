package com.inmaytide.orbit.authorization.oauth2.authentication;

import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.service.UserService;
import com.inmaytide.orbit.framework.core.enums.ClientPlatform;
import com.inmaytide.orbit.framework.core.producer.KafkaProducer;
import com.inmaytide.orbit.framework.core.utils.ApplicationContextHolder;
import com.inmaytide.orbit.framework.log.Constants;
import com.inmaytide.orbit.framework.log.OperationResult;
import com.inmaytide.orbit.framework.log.domain.OperationLogDTO;
import com.inmaytide.orbit.framework.security.domain.SecurityErrorCode;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.springframework.mock.web.MockHttpServletRequest;
import tools.jackson.databind.json.JsonMapper;

import java.util.concurrent.CompletableFuture;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_PLATFORM;
import static com.inmaytide.orbit.authorization.oauth2.authentication.UsernamePasswordAuthenticationToken.PARAMETER_NAME_TENANT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginAuditLogPublisherTests {

    private final KafkaProducer kafkaProducer = mock(KafkaProducer.class);

    private final UserService userService = mock(UserService.class);

    private final LoginAuditLogPublisher publisher = new LoginAuditLogPublisher(
            kafkaProducer, userService, JsonMapper.builder().build());

    @Test
    void buildsSanitizedSuccessfulLoginAudit() {
        MockHttpServletRequest request = loginRequest();
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "user-1",
                "password-hash",
                Map.of(
                        PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name(),
                        PARAMETER_NAME_TENANT_ID, "tenant-1"
                ),
                List.of()
        );

        OperationLogDTO result = withApplicationName(() -> publisher.buildSuccessLog(request, authentication));

        assertThat(result.getOperatedAt()).isNotNull();
        assertThat(result.getTenantId()).isEqualTo("tenant-1");
        assertThat(result.getOperatedBy()).isEqualTo("user-1");
        assertThat(result.getOperationType()).isEqualTo("OTHER");
        assertThat(result.getOperation()).isEqualTo("用户登录成功");
        assertThat(result.getResourceType()).isEqualTo("User");
        assertThat(result.getResourceId()).isEqualTo("user-1");
        assertThat(result.getOperateResult()).isEqualTo(OperationResult.SUCCESS.getValue());
        assertThat(result.getSourceIp()).isEqualTo("192.168.1.10");
        assertThat(result.getRequestBody())
                .contains("\"username\":\"alice\"")
                .doesNotContain("password");
    }

    @Test
    void attributesFailedLoginToKnownUserWithoutExposingPassword() {
        User user = new User();
        user.setId("user-1");
        user.setTenantId("tenant-1");
        when(userService.getByUsername("alice")).thenReturn(Optional.of(user));

        OperationLogDTO result = withApplicationName(
                () -> publisher.buildFailureLog(loginRequest(), SecurityErrorCode.INVALID_CREDENTIALS)
        );

        assertThat(result.getTenantId()).isEqualTo("tenant-1");
        assertThat(result.getOperatedBy()).isEqualTo("user-1");
        assertThat(result.getOperation()).isEqualTo("用户登录失败");
        assertThat(result.getOperateResult()).isEqualTo(OperationResult.FAILURE.getValue());
        assertThat(result.getErrorDescription())
                .isEqualTo("INVALID_CREDENTIALS, Invalid username or password");
        assertThat(result.getRequestBody())
                .contains("\"username\":\"alice\"")
                .doesNotContain("password");
    }

    @Test
    void publishesSuccessfulLoginToOperationLogTopic() {
        when(kafkaProducer.send(eq(Constants.KAFKA_TOPIC_OPERATION_LOG), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "user-1",
                "password-hash",
                Map.of(
                        PARAMETER_NAME_PLATFORM, ClientPlatform.WEB.name(),
                        PARAMETER_NAME_TENANT_ID, "tenant-1"
                ),
                List.of()
        );

        try (MockedStatic<ApplicationContextHolder> mocked = mockStatic(ApplicationContextHolder.class)) {
            mocked.when(ApplicationContextHolder::getApplicationName).thenReturn("authorization");
            publisher.success(loginRequest(), authentication);
        }

        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(kafkaProducer, timeout(1_000)).send(eq(Constants.KAFKA_TOPIC_OPERATION_LOG), message.capture());
        assertThat(message.getValue())
                .contains("\"operation\":\"用户登录成功\"")
                .contains("\"tenantId\":\"tenant-1\"")
                .doesNotContain("password-hash");
    }

    private static MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr("10.0.0.20");
        request.addHeader("X-Forwarded-For", "192.168.1.10, 10.0.0.20");
        request.setAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_STARTED_AT_ATTRIBUTE,
                System.currentTimeMillis() - 20);
        request.setAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_USERNAME_ATTRIBUTE, "alice");
        request.setAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_PLATFORM_ATTRIBUTE, "WEB");
        request.setAttribute(CustomizedUsernamePasswordAuthenticationFilter.LOGIN_FORCED_REPLACEMENT_ATTRIBUTE, false);
        return request;
    }

    private static OperationLogDTO withApplicationName(java.util.function.Supplier<OperationLogDTO> action) {
        try (MockedStatic<ApplicationContextHolder> mocked = mockStatic(ApplicationContextHolder.class)) {
            mocked.when(ApplicationContextHolder::getApplicationName).thenReturn("authorization");
            return action.get();
        }
    }

}
