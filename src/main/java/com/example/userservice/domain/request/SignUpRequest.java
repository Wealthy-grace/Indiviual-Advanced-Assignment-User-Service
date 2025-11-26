package com.example.userservice.domain.request;


import com.example.userservice.persistence.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignUpRequest {

    @NotBlank(message = "Full name is required")
    @Size(max = 255, message = "Full name cannot exceed 255 characters")
    private String fullName;

    @NotBlank(message = "Username is required")
    @Size(min = 4, max = 30, message = "Username must be between 4 and 30 characters")
    @Pattern(
            regexp = "^[a-zA-Z0-9._-]{4,30}$",
            message = "Username can contain letters, numbers, dots, underscores, and hyphens"
    )
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email address")
    @Size(max = 255, message = "Email cannot exceed 255 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    @Pattern(
            regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,100}$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
    )
    private String password;

    @NotBlank(message = "Telephone is required")
    @Size(max = 255, message = "Telephone cannot exceed 255 characters")
    @Pattern(regexp = "^(?:\\+31|0)[1-9]\\d{8}$", message = "Telephone number must be a valid Dutch phone number")
    private String telephone;

    @NotBlank(message = "Address is required")
    @Size(max = 255, message = "Address cannot exceed 255 characters")
    private String address;

    private String role; // optional

    //private String keycloakId;

    @NotBlank(message = "Image is required")
    @Size(max = 255, message = "Image cannot exceed 255 characters")
    private String image;
}
