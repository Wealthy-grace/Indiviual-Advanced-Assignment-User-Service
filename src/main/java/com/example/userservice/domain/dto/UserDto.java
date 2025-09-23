package com.example.userservice.domain.dto;



import com.example.userservice.persistence.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class UserDto {


    private Long id;
    private String fullName;
    private String username;
    private String password;
    private String email;
    private String telephone;
    private String address;
    private String role;
    private String image;
    private String token;

    public static UserDto fromEntity(UserEntity user) {
        return UserDto.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .telephone(user.getTelephone())
                .address(user.getAddress())
                .role(user.getRole().name())
                .image(user.getImage())
                .build(); // token is not set here — it's set separately after building
    }

    // ✅ REMOVE THIS BROKEN MANUAL SETTER
    // public void setToken(String jwtToken) { }
}
