package com.example.userservice.business.Converter;


;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import com.example.userservice.persistence.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class UserConverDto {
    private final PasswordEncoder passwordEncoder;
    public  UserDto mapToDTO(UserEntity entity) {
        return UserDto.builder()
                .id(entity.getId())
                .fullName(entity.getFullName())
                .username(entity.getUsername())
                .email(entity.getEmail())
                .telephone(entity.getTelephone())
                .address(entity.getAddress())
                .password(passwordEncoder.encode(entity.getPassword()))
                .role(String.valueOf(entity.getRole().name()))
                .image(entity.getImage())
                .build();
    }


    public  UserEntity mapToEntity(SignUpRequest dto) {
        return UserEntity.builder()
                //.id(dto.getId())
                .fullName(dto.getFullName())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .telephone(dto.getTelephone())
                .address(dto.getAddress())
                .password(passwordEncoder.encode(dto.getPassword()))
                .role(Role.valueOf(dto.getRole().name()))
                //.role(Role.valueOf(dto.getRole()))
                .image(dto.getImage())
                .build();
    }
}
