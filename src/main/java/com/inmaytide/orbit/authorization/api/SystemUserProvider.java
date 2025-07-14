package com.inmaytide.orbit.authorization.api;

import com.inmaytide.orbit.commons.business.SystemUserService;
import com.inmaytide.orbit.commons.domain.SystemUser;
import org.springframework.web.bind.annotation.*;

/**
 * @author inmaytide
 * @since 2024/12/18
 */
@RestController
@RequestMapping("/api/system-users")
public class SystemUserProvider {

    private final SystemUserService service;

    public SystemUserProvider(SystemUserService service) {
        this.service = service;
    }

    @GetMapping("{id}")
    public SystemUser get(@PathVariable String id) {
        return service.get(id);
    }
}

