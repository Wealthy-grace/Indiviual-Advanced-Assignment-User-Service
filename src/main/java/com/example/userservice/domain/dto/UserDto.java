package com.example.userservice.domain.dto;

import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User Data Transfer Object
 *
 * SECURITY:
 * - Password is excluded from JSON serialization (@JsonIgnore)
 * - Token is excluded from JSON serialization (@JsonIgnore)
 * - Only safe data is exposed to the client
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDto {

    private Long id;

    @NotBlank(message = "Full name is required")
    private String fullName;

    @NotBlank(message = "Username is required")
    private String username;

    /**
     * PASSWORD SECURITY: This field is NEVER sent to the client
     * @JsonIgnore ensures it's excluded from JSON responses
     * Even if the password is set in the DTO, it won't be serialized
     */
    @JsonIgnore
    private String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;

    private String telephone;

    private String address;

    private Role role;

    private String image;

    /**
     * Keycloak user ID - can be exposed as it's needed for linking
     * If you want to hide this too, add @JsonIgnore
     */
    private String keycloakId;

    /**
     * TOKEN SECURITY: Token should not be stored or returned in user DTO
     * @JsonIgnore ensures it's excluded from JSON responses
     */
    @JsonIgnore
    private String token;

    /**
     * Convert UserEntity to UserDto
     * Password is automatically excluded from JSON due to @JsonIgnore
     */
    public static UserDto fromEntity(UserEntity entity) {
        if (entity == null) {
            return null;
        }

        return UserDto.builder()
                .id(entity.getId())
                .fullName(entity.getFullName())
                .username(entity.getUsername())
                // Password is NOT included here - security best practice
                .email(entity.getEmail())
                .telephone(entity.getTelephone())
                .address(entity.getAddress())
                .role(entity.getRole())
                .image(entity.getImage())
                .keycloakId(entity.getKeycloakId())
                .build();
    }

    /**
     * Create a public-safe version of UserDto
     * Use this when you want extra control over what's exposed
     */
    public UserDto toPublicDto() {
        return UserDto.builder()
                .id(this.id)
                .fullName(this.fullName)
                .username(this.username)
                // password excluded
                .email(this.email)
                .telephone(this.telephone)
                .address(this.address)
                .role(this.role)
                .image(this.image)
                // keycloakId can be excluded here if you want extra privacy
                .build();
    }

    /**
     * Create a minimal public profile (for displaying to other users)
     * Only includes non-sensitive information
     */
    public UserDto toMinimalProfile() {
        return UserDto.builder()
                .id(this.id)
                .fullName(this.fullName)
                .username(this.username)
                .image(this.image)
                .role(this.role)
                .build();
    }
}






