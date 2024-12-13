package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.UserAssociation;
import com.inmaytide.orbit.authorization.domain.UserAssociationPrimaryKey;
import com.inmaytide.orbit.commons.constants.UserAssociationCategory;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author inmaytide
 * @since 2024/12/12
 */
@Repository
public interface UserAssociationRepository extends JpaRepository<UserAssociation, UserAssociationPrimaryKey> {

    @Query("select ua from UserAssociation ua where ua.id.user = :user and ua.id.category = :category")
    List<UserAssociation> findByUserAndCategory(@Param("user") Long user, @Param("category") UserAssociationCategory category);
}
