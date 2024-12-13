package com.inmaytide.orbit.authorization.service;

import com.inmaytide.exception.web.ObjectNotFoundException;
import com.inmaytide.orbit.authorization.configuration.ApplicationProperties;
import com.inmaytide.orbit.authorization.configuration.ErrorCode;
import com.inmaytide.orbit.authorization.domain.User;
import com.inmaytide.orbit.authorization.domain.UserAssociation;
import com.inmaytide.orbit.authorization.repository.*;
import com.inmaytide.orbit.commons.business.SystemUserService;
import com.inmaytide.orbit.commons.constants.Bool;
import com.inmaytide.orbit.commons.constants.Constants;
import com.inmaytide.orbit.commons.constants.Roles;
import com.inmaytide.orbit.commons.constants.UserAssociationCategory;
import com.inmaytide.orbit.commons.domain.*;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.math.NumberUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Primary
@Service
public class DefaultSystemUserService implements SystemUserService {

    private final UserRepository userRepository;

    private final UserAssociationRepository userAssociationRepository;

    private final OrganizationRepository organizationRepository;

    private final PositionRepository positionRepository;

    private final RoleRepository roleRepository;

    private final ApplicationProperties properties;

    private DefaultSystemUserService self;

    public DefaultSystemUserService(UserRepository userRepository, UserAssociationRepository userAssociationRepository, OrganizationRepository organizationRepository, PositionRepository positionRepository, RoleRepository roleRepository, ApplicationProperties properties) {
        this.userRepository = userRepository;
        this.userAssociationRepository = userAssociationRepository;
        this.organizationRepository = organizationRepository;
        this.positionRepository = positionRepository;
        this.roleRepository = roleRepository;
        this.properties = properties;
    }

    @Lazy
    @Resource
    public void setSelf(DefaultSystemUserService self) {
        this.self = self;
    }

    @Override
    @Cacheable(cacheNames = Constants.CacheNames.USER_DETAILS, key = "#id")
    public SystemUser get(Serializable id) {
        if (Objects.equals(id, Robot.getInstance().getId())) {
            return Robot.getInstance().toSystemUser();
        }
        if (!NumberUtils.isCreatable(Objects.toString(id, ""))) {
            throw new ObjectNotFoundException(ErrorCode.E_0x02100001, Objects.toString(id, "null"));
        }
        User user = userRepository.findById(NumberUtils.createLong(Objects.toString(id))).orElseThrow(() -> new ObjectNotFoundException(ErrorCode.E_0x02100001, Objects.toString(id, "null")));
        return transferUserToSystemUser(user);
    }

    @Override
    public Optional<SystemUser> findByUsername(String username) {
        Specification<User> specification = (root, query, cb) -> {
            return cb.or(
                    cb.equal(root.get("telephoneNumber"), username),
                    cb.equal(root.get("loginName"), username),
                    cb.equal(root.get("email"), username),
                    cb.equal(root.get("employeeId"), username)
            );
        };
        return userRepository.findOne(specification).map(u -> self.get(u.getId()));
    }

    private <T> T createObjectCopiedFields(Object source, Supplier<T> supplier) {
        T t = supplier.get();
        BeanUtils.copyProperties(source, t);
        return t;
    }

    private SystemUser transferUserToSystemUser(User user) {
        Objects.requireNonNull(user);
        SystemUser systemUser = new SystemUser();
        BeanUtils.copyProperties(user, systemUser);
        setRoles(systemUser, user.getIsTenantAdministrator());
        setPermissions(systemUser);
        setOrganizations(systemUser);
        setPositions(systemUser);
        return systemUser;
    }

    private void setOrganizations(SystemUser user) {
        List<UserAssociation> associations = userAssociationRepository.findByUserAndCategory(user.getId(), UserAssociationCategory.ORGANIZATION);
        List<Organization> organizations = organizationRepository
                .findAllById(associations.stream().map(e -> e.getId().getAssociated()).toList())
                .stream()
                .map(e -> createObjectCopiedFields(e, Organization::new))
                .toList();
        user.setOrganizations(organizations);
        associations.stream()
                .filter(e -> e.getDefaulted() == Bool.Y)
                .findFirst()
                .flatMap(e -> organizations.stream().filter(o -> Objects.equals(o.getId(), e.getId().getAssociated())).findFirst())
                .ifPresent(o -> {
                    user.setOrganizationId(o.getId());
                    user.setOrganizationName(o.getName());
                });

    }

    private void setPositions(SystemUser user) {
        List<UserAssociation> associations = userAssociationRepository.findByUserAndCategory(user.getId(), UserAssociationCategory.POSITION);
        List<Position> positions = positionRepository
                .findAllById(associations.stream().map(e -> e.getId().getAssociated()).toList())
                .stream()
                .map(e -> createObjectCopiedFields(e, Position::new))
                .toList();
        user.setPositions(positions);
        associations.stream()
                .filter(e -> e.getDefaulted() == Bool.Y)
                .findFirst()
                .flatMap(e -> positions.stream().filter(o -> Objects.equals(o.getId(), e.getId().getAssociated())).findFirst())
                .ifPresent(o -> {
                    user.setPositionId(o.getId());
                    user.setPositionName(o.getName());
                });
    }

    private void setRoles(SystemUser user, Bool isTenantAdministrator) {
        List<Long> ids = userAssociationRepository
                .findByUserAndCategory(user.getId(), UserAssociationCategory.ROLE)
                .stream()
                .map(e -> e.getId().getAssociated())
                .toList();
        List<Role> roles = new ArrayList<>(roleRepository.findAllById(ids).stream().map(e -> createObjectCopiedFields(e, Role::new)).toList());
        // 系统是否启用了超级管理员&&用户的登录名和配置指定的超级管理员用户名是否匹配
        if (properties.isEnableSuperAdministrator() && properties.getSuperAdministratorLoginNames().contains(user.getLoginName())) {
            roles.add(new Role(Roles.ROLE_S_ADMINISTRATOR.name(), "超级管理员"));
        }
        // 用户是否是租户管理员
        if (isTenantAdministrator == Bool.Y) {
            roles.add(new Role(Roles.ROLE_T_ADMINISTRATOR.name(), "租户管理员"));
        }
        // 用户是否为配置的系统内部机器人
        if (Objects.equals(user.getId(), Robot.getInstance().getId())) {
            roles.add(new Role(Roles.ROLE_ROBOT.name(), "系统内部机器人"));
        }
        user.setRoles(roles);
    }

    private void setPermissions(SystemUser user) {
        Permission permission = new Permission();
        permission.setRoles(user.getRoles().stream().map(Role::getCode).toList());
        permission.setAuthorities(findAuthorityCodes(user));
        permission.setOrganizations(findAuthorizedOrganizationIds(user));
        permission.setSpecifiedOrganizations(permission.getOrganizations());
        permission.setAreas(findAuthorizedAreaIds(user));
        permission.setSpecifiedAreas(permission.getAreas());
        user.setPermission(permission);
    }

    private List<Long> findAuthorizedOrganizationIds(SystemUser user) {
        List<String> roleCodes = user.getRoles().stream().map(Role::getCode).toList();
        if (roleCodes.isEmpty()) {
            return List.of();
        }
        // 超级管理员/租户管理员有所属租户的所有权限
        if (roleCodes.contains(Roles.ROLE_S_ADMINISTRATOR.name()) || roleCodes.contains(Roles.ROLE_T_ADMINISTRATOR.name())) {
            return organizationRepository.findIdsByTenant(user.getTenant());
        }
        // 内部机器人拥有所有权限
        if (roleCodes.contains(Roles.ROLE_ROBOT.name())) {
            return organizationRepository.findIds();
        }
        return organizationRepository.findIdsByRoleIds(UserAssociationCategory.ORGANIZATION.name(), user.getRoles().stream().map(Role::getId).toList());
    }

    private List<Long> findAuthorizedAreaIds(SystemUser user) {
        return List.of();
    }

    private List<String> findAuthorityCodes(SystemUser user) {
        return List.of();
    }

}
