package io.ysf.springsecurityjwt.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.ysf.springsecurityjwt.dto.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);

	Optional<User> findByCode(String code);

	Boolean existsByUsername(String username);

	Boolean existsByCode(String code);

	Boolean existsByEmail(String email);
}