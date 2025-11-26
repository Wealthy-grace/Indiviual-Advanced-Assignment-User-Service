package com.example.userservice.persistence.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String fullName;
    @Column(unique = true)
    private String username;
    private String email;
    private String password;
    private String telephone;
    private String address;

    @Enumerated(EnumType.STRING)
    private Role role;
    // ✅ ADD THIS FIELD
    @Column(name = "keycloak_id")
    private String keycloakId;
    private String image;

    public void setEnabled(boolean b) {
    }
}
