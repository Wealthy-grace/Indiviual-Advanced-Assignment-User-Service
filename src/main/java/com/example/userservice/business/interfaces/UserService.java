package com.example.userservice.business.interfaces;


import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;

import java.util.List;

public interface UserService {

    SignUpResponse createUser(SignUpRequest signUpRequest);

    LonginResponse Login(LoginRequest loginRequest);

    UserDto getUserByUsername(String username);
;
    UserDto getUserById(Long id);

    public List<UserDto> getAllUsers();

    UserDto updateUser(UserDto userDto);

    void deleteUser(Long id);

    public Role getUserRole(String username);

    public UserDto getUserProfile(String username);

    public Role getUserRole(Long id);
}
