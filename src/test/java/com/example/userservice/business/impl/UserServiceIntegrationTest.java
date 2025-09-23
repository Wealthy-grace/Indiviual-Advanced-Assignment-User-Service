package com.example.userservice.business.impl;

import com.example.userservice.configuration.exceptions.UserAlreadyExistsException;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import com.example.userservice.persistence.repository.UserRepo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class UserServiceIntegrationTest {

    @Autowired
    private UserServiceImpl userService;

    @Autowired
    private UserRepo userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private UserEntity existingUser;

    @BeforeEach
    void setUp() {
        // Create an existing user with encoded password
        existingUser = UserEntity.builder()
                .username("existinguser")
                .email("existing@test.com")
                .password(passwordEncoder.encode("password123"))
                .fullName("Existing User")
                .telephone("0687654321")
                .address("Existing Address")
                .role(Role.ROLE_STUDENT)
                .build();
        userRepository.save(existingUser);
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    void createUser_Success() {
        SignUpRequest request = SignUpRequest.builder()
                .username("user1")
                .email("user1@test.com")
                .password("password123")
                .fullName("User One")
                .telephone("0611111111")
                .address("Address One")
                .role(Role.ROLE_STUDENT)
                .build();

        SignUpResponse response = userService.createUser(request);

        assertNotNull(response);
        assertEquals("User created successfully", response.getMessage());
        assertNotNull(response.getUser());
        assertEquals("user1", response.getUser().getUsername());
        assertTrue(userRepository.existsByUsername("user1"));
    }

    @Test
    void createUser_DuplicateUsername_ThrowsException() {
        SignUpRequest request1 = SignUpRequest.builder()
                .username("user2")
                .email("user2@test.com")
                .password("password123")
                .fullName("User Two")
                .telephone("0611111112")
                .address("Address Two")
                .role(Role.ROLE_STUDENT)
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user2") // duplicate username
                .email("user2diff@test.com")
                .password("password456")
                .fullName("User Two Different")
                .telephone("0611111113")
                .address("Address Three")
                .role(Role.ROLE_ADMIN)
                .build();

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request2));
    }

    @Test
    void createUser_DuplicateEmail_ThrowsException() {
        SignUpRequest request1 = SignUpRequest.builder()
                .username("user3")
                .email("user3@test.com")
                .password("password123")
                .fullName("User Three")
                .telephone("0611111114")
                .address("Address Four")
                .role(Role.ROLE_STUDENT)
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user3diff")
                .email("user3@test.com") // duplicate email
                .password("password456")
                .fullName("User Three Different")
                .telephone("0611111115")
                .address("Address Five")
                .role(Role.ROLE_ADMIN)
                .build();

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request2));
    }

    @Test
    void createUser_DuplicateTelephone_ThrowsException() {
        SignUpRequest request1 = SignUpRequest.builder()
                .username("user4")
                .email("user4@test.com")
                .password("password123")
                .fullName("User Four")
                .telephone("0611111116")
                .address("Address Six")
                .role(Role.ROLE_STUDENT)
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user4diff")
                .email("user4diff@test.com")
                .password("password456")
                .fullName("User Four Different")
                .telephone("0611111116") // duplicate telephone
                .address("Address Seven")
                .role(Role.ROLE_ADMIN)
                .build();

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request2));
    }

    @Test
    void login_Success() {
        // First, create a user
        SignUpRequest request = SignUpRequest.builder()
                .username("loginuser")
                .email("loginuser@test.com")
                .password("password123")
                .fullName("Login User")
                .telephone("0611111117")
                .address("Address Eight")
                .role(Role.ROLE_STUDENT)
                .build();
        userService.createUser(request);

        LonginResponse response = userService.Login(LoginRequest.builder()
                .username("loginuser")
                .password("password123")
                .build());

        assertNotNull(response);
        assertEquals("Congratulations, you have successfully logged in!", response.getMessage());
        assertNotNull(response.getUser());
        assertEquals("loginuser", response.getUser().getUsername());
    }

    @Test
    void login_InvalidCredentials_ThrowsException() {
        SignUpRequest request = SignUpRequest.builder()
                .username("loginuser2")
                .email("loginuser2@test.com")
                .password("password123")
                .fullName("Login User 2")
                .telephone("0611111118")
                .address("Address Nine")
                .role(Role.ROLE_STUDENT)
                .build();
        userService.createUser(request);

        assertThrows(RuntimeException.class, () -> userService.Login(LoginRequest.builder()
                .username("loginuser2")
                .password("wrongpassword")
                .build()));
    }
}
