package com.inmaytide.orbit.authorization.repository;

import com.inmaytide.orbit.authorization.domain.Organization;
import com.inmaytide.orbit.authorization.domain.Position;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author inmaytide
 * @since 2024/12/12
 */
@Repository
public interface PositionRepository extends JpaRepository<Position, Long> {
}
