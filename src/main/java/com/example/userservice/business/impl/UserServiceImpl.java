package com.example.userservice.business.impl;

import com.example.userservice.business.Converter.UserConverDto;
import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.configuration.exceptions.UserAlreadyExistsException;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import com.example.userservice.persistence.repository.UserRepo;
import com.example.userservice.security.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserConverDto userConverDto;

    @Override
    public SignUpResponse createUser(SignUpRequest signUpRequest) {
        // check if user already exists
        CheckIfUserExists(signUpRequest);

        // create user entity
        UserEntity user = userConverDto.mapToEntity(signUpRequest);

        // save user
        userRepository.save(user);

        return SignUpResponse.builder()
                .message("User created successfully")
                .user(userConverDto.mapToDTO(user))
                .build();
    }

    @Override
    public LonginResponse Login(LoginRequest loginRequest) {
        try {
            // Authenticate user credentials
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // Set authentication context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Load user data
            UserEntity user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found after authentication"));

            // Generate JWT token
            String jwtToken = jwtUtils.generateTokenFromUsername(user.getUsername());

            // Convert user entity to DTO
            UserDto userDto = UserDto.fromEntity(user);

            // Create LoginResponse
            LonginResponse response = new LonginResponse();
            response.setMessage("Congratulations, you have successfully logged in!");
            response.setUser(userDto);
            response.setToken(jwtToken);

            return response;

        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid username or password");
        } catch (Exception e) {
            throw new RuntimeException("Login failed: " + e.getMessage());
        }
    }

    @Override
    public UserDto getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(userConverDto::mapToDTO)
                .orElse(null);
    }

    @Override
    public UserDto getUserById(Long id) {
        return userRepository.findById(id)
                .map(UserDto::fromEntity)
                .orElse(null);
    }

    @Override
    public UserDto getUserProfile(String username) {
        return userRepository.findByUsername(username)
                .map(UserDto::fromEntity)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    @Override
    public List<UserDto> getAllUsers() {
        List<UserEntity> users = userRepository.findAll();
        return users.stream()
                .map(UserDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public Role getUserRole(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
        return user.getRole();
    }

    @Override
    public Role getUserRole(Long id) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));
        return user.getRole();
    }

    @Override
    public UserDto updateUser(UserDto userDto) {
        Optional<UserEntity> optionalUser = userRepository.findById(userDto.getId());
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("User not found with ID: " + userDto.getId());
        }

        UserEntity user = optionalUser.get();
        user.setEmail(userDto.getEmail());
        user.setFullName(userDto.getFullName());
        user.setUsername(userDto.getUsername());
        user.setImage(userDto.getImage());
        user.setTelephone(userDto.getTelephone());
        user.setAddress(userDto.getAddress());

        userRepository.save(user);

        return UserDto.fromEntity(user);
    }

    @Override
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("User not found with ID: " + id);
        }
        userRepository.deleteById(id);
    }

    private void CheckIfUserExists(SignUpRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        if (userRepository.existsByAddress(request.getAddress())) {
            throw new UserAlreadyExistsException("Address already exists: " + request.getAddress());
        }

        if (userRepository.existsByFullName(request.getFullName())) {
            throw new UserAlreadyExistsException("Full name already exists: " + request.getFullName());
        }

        if (userRepository.existsByTelephone(request.getTelephone())) {
            throw new UserAlreadyExistsException("Telephone already exists: " + request.getTelephone());
        }
    }
}