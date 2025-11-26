package com.example.userservice.persistence.repository;


import com.example.userservice.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * User Repository with CASE-INSENSITIVE username queries
 *
 * This fixes the issue where Keycloak returns "jennifer275" (lowercase)
 * but the database has "Jennifer275" (capital J)
 */
@Repository
public interface UserRepo extends JpaRepository<UserEntity, Long> {

    /**
     * Find user by username (CASE-INSENSITIVE)
     *
     * Works with both "Jennifer275" and "jennifer275"
     */
    @Query("SELECT u FROM UserEntity u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<UserEntity> findByUsername(@Param("username") String username);

    /**
     * Find user by email (CASE-INSENSITIVE)
     */
    @Query("SELECT u FROM UserEntity u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<UserEntity> findByEmail(@Param("email") String email);

    /**
     * Find user by Keycloak ID
     */
    Optional<UserEntity> findByKeycloakId(String keycloakId);

    /**
     * Check if username exists (CASE-INSENSITIVE)
     */
    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE LOWER(u.username) = LOWER(:username)")
    boolean existsByUsername(@Param("username") String username);

    /**
     * Check if email exists (CASE-INSENSITIVE)
     */
    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE LOWER(u.email) = LOWER(:email)")
    boolean existsByEmail(@Param("email") String email);

    /**
     * Check if address exists (CASE-INSENSITIVE)
     */
    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE LOWER(u.address) = LOWER(:address)")
    boolean existsByAddress(@Param("address") String address);

    /**
     * Check if full name exists (CASE-INSENSITIVE)
     */
    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE LOWER(u.fullName) = LOWER(:fullName)")
    boolean existsByFullName(@Param("fullName") String fullName);

    /**
     * Check if telephone exists
     */
    boolean existsByTelephone(String telephone);

    /**
     * Delete user by username (CASE-INSENSITIVE)
     */
    @Query("DELETE FROM UserEntity u WHERE LOWER(u.username) = LOWER(:username)")
    void deleteByUsername(@Param("username") String username);
}




