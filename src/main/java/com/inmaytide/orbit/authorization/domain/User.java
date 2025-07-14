package com.inmaytide.orbit.authorization.domain;

import com.inmaytide.orbit.Version;
import com.inmaytide.orbit.commons.constants.Bool;
import com.inmaytide.orbit.commons.constants.Languages;
import com.inmaytide.orbit.commons.constants.UserStatus;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDate;

/**
 * @author inmaytide
 * @since 2024/12/6
 */
@Entity
@Table(name = "user", schema = "uaa")
public class User implements Serializable {

    @Serial
    private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

    @Id
    private String id;

    private String tenant;

    @Enumerated(EnumType.STRING)
    private Bool isTenantAdministrator;

    private String rank;

    @Transient
    private String rankName;

    private Integer sequence;

    private String name;

    private String gender;

    @Transient
    private String genderName;

    private LocalDate birthday;

    @Transient
    private String identificationNumber;

    private String loginName;

    private String password;

    private Instant passwordExpireAt;

    private String telephoneNumber;

    private String email;

    @Enumerated(EnumType.STRING)
    private Languages lang;

    private String avatar;

    private String signature;

    private String photo;

    @Enumerated(EnumType.STRING)
    private UserStatus status;

    private Instant statusTime;

    private String proxy;

    private String personnelStatus;

    @Transient
    private String personnelStatusName;

    private String employeeId;

    private LocalDate joinDate;

    private LocalDate employmentConfirmationDate;

    private LocalDate resignationDate;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public Bool getIsTenantAdministrator() {
        return isTenantAdministrator;
    }

    public void setIsTenantAdministrator(Bool isTenantAdministrator) {
        this.isTenantAdministrator = isTenantAdministrator;
    }

    public String getRank() {
        return rank;
    }

    public void setRank(String rank) {
        this.rank = rank;
    }

    public String getRankName() {
        return rankName;
    }

    public void setRankName(String rankName) {
        this.rankName = rankName;
    }

    public Integer getSequence() {
        return sequence;
    }

    public void setSequence(Integer sequence) {
        this.sequence = sequence;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getGenderName() {
        return genderName;
    }

    public void setGenderName(String genderName) {
        this.genderName = genderName;
    }

    public LocalDate getBirthday() {
        return birthday;
    }

    public void setBirthday(LocalDate birthday) {
        this.birthday = birthday;
    }

    public String getIdentificationNumber() {
        return identificationNumber;
    }

    public void setIdentificationNumber(String identificationNumber) {
        this.identificationNumber = identificationNumber;
    }

    public String getLoginName() {
        return loginName;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Instant getPasswordExpireAt() {
        return passwordExpireAt;
    }

    public void setPasswordExpireAt(Instant passwordExpireAt) {
        this.passwordExpireAt = passwordExpireAt;
    }

    public String getTelephoneNumber() {
        return telephoneNumber;
    }

    public void setTelephoneNumber(String telephoneNumber) {
        this.telephoneNumber = telephoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Languages getLang() {
        return lang;
    }

    public void setLang(Languages lang) {
        this.lang = lang;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPhoto() {
        return photo;
    }

    public void setPhoto(String photo) {
        this.photo = photo;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public Instant getStatusTime() {
        return statusTime;
    }

    public void setStatusTime(Instant statusTime) {
        this.statusTime = statusTime;
    }

    public String getProxy() {
        return proxy;
    }

    public void setProxy(String proxy) {
        this.proxy = proxy;
    }

    public String getPersonnelStatus() {
        return personnelStatus;
    }

    public void setPersonnelStatus(String personnelStatus) {
        this.personnelStatus = personnelStatus;
    }

    public String getPersonnelStatusName() {
        return personnelStatusName;
    }

    public void setPersonnelStatusName(String personnelStatusName) {
        this.personnelStatusName = personnelStatusName;
    }

    public String getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(String employeeId) {
        this.employeeId = employeeId;
    }

    public LocalDate getJoinDate() {
        return joinDate;
    }

    public void setJoinDate(LocalDate joinDate) {
        this.joinDate = joinDate;
    }

    public LocalDate getEmploymentConfirmationDate() {
        return employmentConfirmationDate;
    }

    public void setEmploymentConfirmationDate(LocalDate employmentConfirmationDate) {
        this.employmentConfirmationDate = employmentConfirmationDate;
    }

    public LocalDate getResignationDate() {
        return resignationDate;
    }

    public void setResignationDate(LocalDate resignationDate) {
        this.resignationDate = resignationDate;
    }
}
