package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.framework.Version;
import com.inmaytide.orbit.framework.core.enums.UserStatus;
import jakarta.persistence.*;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;


/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Data
@Entity
@Table(name = "t_user", schema = "iam")
public class User implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private String id;

    private String tenantId;

    private String employeeNumber;

    private String username;

    private String phone;

    private String password;

    private UserStatus status;

    private String email;

    private Integer deleted = 0;

}
