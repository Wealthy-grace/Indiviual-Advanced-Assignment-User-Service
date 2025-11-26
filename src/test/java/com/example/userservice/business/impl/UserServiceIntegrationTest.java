package com.example.userservice.business.impl;

import com.example.userservice.configuration.exceptions.UserAlreadyExistsException;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;
import com.example.userservice.persistence.entity.UserEntity;
import com.example.userservice.persistence.repository.UserRepo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

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

    //  Mock Keycloak service for integration tests
    @MockitoBean
    private KeycloakUserService keycloakUserService;

    private UserEntity existingUser;

    @BeforeEach
    void setUp() {
        // Clean database before each test
        userRepository.deleteAll();

        // ✅ Mock Keycloak responses for all tests
        when(keycloakUserService.getUserByUsername(anyString())).thenReturn(null);
        when(keycloakUserService.createKeycloakUser(
                anyString(), anyString(), anyString(), anyString(), anyString(), any(Role.class)
        )).thenReturn("keycloak-id-" + System.currentTimeMillis());

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
                .role(String.valueOf(Role.ROLE_STUDENT))
                .build();

        SignUpResponse response = userService.createUser(request);

        assertNotNull(response);
        //  Updated message
        assertEquals("User created successfully. You can now login with Keycloak.", response.getMessage());
        assertNotNull(response.getUser());
        assertEquals("user1", response.getUser().getUsername());
        assertTrue(userRepository.existsByUsername("user1"));

        // ✅ Verify Keycloak was called
        verify(keycloakUserService).createKeycloakUser(
                eq("user1"),
                eq("user1@test.com"),
                eq("password123"),
                eq("User"),
                eq("One"),
                eq(Role.ROLE_STUDENT)
        );
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
                .role(String.valueOf(Role.ROLE_STUDENT))
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user2") // duplicate username
                .email("user2diff@test.com")
                .password("password456")
                .fullName("User Two Different")
                .telephone("0611111113")
                .address("Address Three")
                .role(String.valueOf(Role.ROLE_ADMIN))
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
                .role(String.valueOf(Role.ROLE_STUDENT))
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user3diff")
                .email("user3@test.com") // duplicate email
                .password("password456")
                .fullName("User Three Different")
                .telephone("0611111115")
                .address("Address Five")
                .role(String.valueOf(Role.ROLE_ADMIN))
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
                .role(String.valueOf(Role.ROLE_STUDENT))
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user4diff")
                .email("user4diff@test.com")
                .password("password456")
                .fullName("User Four Different")
                .telephone("0611111116") // duplicate telephone
                .address("Address Seven")
                .role(String.valueOf(Role.ROLE_ADMIN))
                .build();

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request2));
    }

    @Test
    void createUser_DuplicateAddress_ThrowsException() {
        SignUpRequest request1 = SignUpRequest.builder()
                .username("user5")
                .email("user5@test.com")
                .password("password123")
                .fullName("User Five")
                .telephone("0611111118")
                .address("Address Eight")
                .role(String.valueOf(Role.ROLE_STUDENT))
                .build();

        userService.createUser(request1);

        SignUpRequest request2 = SignUpRequest.builder()
                .username("user5diff")
                .email("user5diff@test.com")
                .password("password456")
                .fullName("User Five Different")
                .telephone("0611111119")
                .address("Address Eight") // duplicate address
                .role(String.valueOf(Role.ROLE_ADMIN))
                .build();

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request2));
    }





}


















