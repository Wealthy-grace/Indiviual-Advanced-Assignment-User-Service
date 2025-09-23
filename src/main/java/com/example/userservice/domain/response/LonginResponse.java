package com.example.userservice.domain.response;


import com.example.userservice.domain.dto.UserDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class LonginResponse {

    private String message;

    private String token;

    private UserDto user;
}
