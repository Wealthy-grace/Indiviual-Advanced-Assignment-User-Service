package com.example.userservice.persistence.repository;


import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<UserEntity, Long> {


    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);

    Optional<UserEntity> findByRole(Role role);
    boolean existsByEmail(String email);

    boolean existsByTelephone(String telephone);

    boolean existsByAddress(String address);

    boolean existsByFullName (String fullName);
}
