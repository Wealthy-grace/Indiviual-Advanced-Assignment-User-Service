package com.example.userservice.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.configuration.exceptions.UserAlreadyExistsException;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc(addFilters = false)
@WebMvcTest(AuthController.class)
@TestPropertySource(properties = {
        "keycloak.auth-server-url=http://localhost:8080",
        "keycloak.realm=friendly-housing"
})
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserService userService;

    private SignUpRequest signUpRequest;
    private LoginRequest loginRequest;
    private UserDto userDto;
    private SignUpResponse signUpResponse;

    @TestConfiguration
    static class ControllerMockConfig {
        @Bean
        public UserService userService() {
            return Mockito.mock(UserService.class);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return Mockito.mock(PasswordEncoder.class);
        }
    }

    @BeforeEach
    void setUp() {
        signUpRequest = SignUpRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("Password@123")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role(String.valueOf(Role.ROLE_STUDENT))
                .image("https://example.com/image.jpg")
                .build();

        loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("Password@123")
                .build();

        userDto = UserDto.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role(Role.ROLE_STUDENT)
                .image("https://example.com/image.jpg")
                .build();

        signUpResponse = SignUpResponse.builder()
                .message("User created successfully. You can now login with Keycloak.")
                .user(userDto)
                .build();
    }

    // ========== SIGNUP TESTS ==========

    @Test
    void registerUser_Success() throws Exception {
        when(userService.createUser(any(SignUpRequest.class))).thenReturn(signUpResponse);

        mockMvc.perform(post("/api/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User created successfully. You can now login with Keycloak."))
                .andExpect(jsonPath("$.user.username").value("testuser"));
    }

    @Test
    void registerUser_UserAlreadyExists() throws Exception {
        when(userService.createUser(any(SignUpRequest.class)))
                .thenThrow(new UserAlreadyExistsException("User already exists with username: testuser"));

        mockMvc.perform(post("/api/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andDo(print())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("User already exists"))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void registerUser_Failure() throws Exception {
        when(userService.createUser(any(SignUpRequest.class)))
                .thenThrow(new RuntimeException("Database error"));

        mockMvc.perform(post("/api/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Signup failed"));
    }

    // ========== LOGIN TESTS ==========

    @Test
    void loginUser_Success() throws Exception {
        when(userService.Login(any(LoginRequest.class)))
                .thenReturn(LonginResponse.builder()
                        .message("Login successful")
                        .user(userDto)
                        .build());

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.user.username").value("testuser"))
                .andExpect(jsonPath("$.keycloakTokenUrl").exists())
                .andExpect(jsonPath("$.instructions").exists());
    }

    @Test
    void loginUser_Failure() throws Exception {
        when(userService.Login(any(LoginRequest.class)))
                .thenThrow(new RuntimeException("Invalid username or password"));

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Login failed"))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    // ========== GET USER TESTS ==========

    @Test
    void getUser_UserExists() throws Exception {
        when(userService.getUserByUsername("testuser")).thenReturn(userDto);

        mockMvc.perform(get("/api/auth/user/testuser"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    void getUser_UserNotExists() throws Exception {
        when(userService.getUserByUsername("nonexistent")).thenReturn(null);

        mockMvc.perform(get("/api/auth/user/nonexistent"))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    void getUser_ServiceError() throws Exception {
        when(userService.getUserByUsername(anyString()))
                .thenThrow(new RuntimeException("Database error"));

        mockMvc.perform(get("/api/auth/user/testuser"))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Error"));
    }

    // ========== PROFILE TESTS ==========

    @Test
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void getUserProfile_Success() throws Exception {
        when(userService.getUserProfile("testuser")).thenReturn(userDto);

        mockMvc.perform(get("/api/auth/profile"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.username").value("testuser"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    @WithMockUser(username = "nonexistent", roles = {"STUDENT"})
    void getUserProfile_UserNotFound() throws Exception {
        when(userService.getUserProfile("nonexistent"))
                .thenThrow(new RuntimeException("User not found"));

        mockMvc.perform(get("/api/auth/profile"))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Error"));
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void updateUserProfile_Success() throws Exception {
        when(userService.getUserByUsername("testuser")).thenReturn(userDto);
        when(userService.updateUser(any(UserDto.class))).thenReturn(userDto);

        mockMvc.perform(put("/api/auth/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userDto)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    @WithMockUser(username = "nonexistent", roles = {"STUDENT"})
    void updateUserProfile_UserNotFound() throws Exception {

        // Reset any previous mocks and set up the behavior
        Mockito.reset(userService);
        when(userService.getUserByUsername("nonexistent")).thenReturn(null);

        // Create a DTO for the nonexistent user
        UserDto nonexistentUserDto = UserDto.builder()
                .id(999L)
                .username("nonexistent")
                .email("nonexistent@example.com")
                .fullName("Nonexistent User")
                .telephone("0612345679")
                .address("Nonexistent Address")
                .role(Role.ROLE_STUDENT)
                .build();

        mockMvc.perform(put("/api/auth/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(nonexistentUserDto)))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void updateUserProfile_Forbidden_DifferentUser() throws Exception {
        UserDto otherUserDto = UserDto.builder()
                .id(999L)
                .username("otheruser")
                .email("other@example.com")
                .fullName("Other User")
                .telephone("0612345679")
                .address("Other Address")
                .role(Role.ROLE_STUDENT)
                .build();

        when(userService.getUserByUsername("testuser")).thenReturn(userDto);

        mockMvc.perform(put("/api/auth/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(otherUserDto)))
                .andDo(print())
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    // ========== ALL USERS TESTS (ADMIN ONLY) ==========

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getAllUsers_Success() throws Exception {
        List<UserDto> users = Collections.singletonList(userDto);
        when(userService.getAllUsers()).thenReturn(users);

        mockMvc.perform(get("/api/auth/users"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("testuser"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getAllUsers_Failure() throws Exception {
        when(userService.getAllUsers())
                .thenThrow(new RuntimeException("Failed to retrieve users"));

        mockMvc.perform(get("/api/auth/users"))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Error"));
    }

    // ========== USER ROLE TESTS ==========

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getUserRole_Success() throws Exception {
        when(userService.getUserRole("testuser")).thenReturn(Role.ROLE_STUDENT);

        mockMvc.perform(get("/api/auth/user/testuser/role"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ROLE_STUDENT"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getUserRole_UserNotFound() throws Exception {
        when(userService.getUserRole("nonexistent"))
                .thenThrow(new RuntimeException("User not found"));

        mockMvc.perform(get("/api/auth/user/nonexistent/role"))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    @Test
    @WithMockUser(roles = {"PROPERTY_MANAGER"})
    void getUserRole_PropertyManager_Success() throws Exception {
        when(userService.getUserRole("testuser")).thenReturn(Role.ROLE_STUDENT);

        mockMvc.perform(get("/api/auth/user/testuser/role"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ROLE_STUDENT"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getUserRoleById_Success() throws Exception {
        when(userService.getUserRole(1L)).thenReturn(Role.ROLE_STUDENT);

        mockMvc.perform(get("/api/auth/user/id/1/role"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ROLE_STUDENT"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void getUserRoleById_UserNotFound() throws Exception {
        when(userService.getUserRole(999L))
                .thenThrow(new RuntimeException("User not found"));

        mockMvc.perform(get("/api/auth/user/id/999/role"))
                .andDo(print())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("User not found"));
    }

    // ========== DELETE USER TESTS (ADMIN ONLY) ==========

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void deleteUser_Success() throws Exception {
        mockMvc.perform(delete("/api/auth/user/1")
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User deleted successfully"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void deleteUser_UserNotFound() throws Exception {
        doThrow(new RuntimeException("User not found"))
                .when(userService).deleteUser(999L);

        mockMvc.perform(delete("/api/auth/user/999")
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Delete failed"))
                .andExpect(jsonPath("$.message").value("User not found"));
    }

    // ========== DASHBOARD TESTS ==========

    @Test
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void userDashboard_Success() throws Exception {
        mockMvc.perform(get("/api/auth/user/dashboard"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to your dashboard!"))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    @WithMockUser(username = "carrier", roles = {"CARRIER_WORKER"})
    void userDashboard_CarrierWorker_Success() throws Exception {
        mockMvc.perform(get("/api/auth/user/dashboard"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to your dashboard!"))
                .andExpect(jsonPath("$.username").value("carrier"));
    }

    @Test
    @WithMockUser(username = "manager", roles = {"PROPERTY_MANAGER"})
    void userDashboard_PropertyManager_Success() throws Exception {
        mockMvc.perform(get("/api/auth/user/dashboard"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to your dashboard!"))
                .andExpect(jsonPath("$.username").value("manager"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void adminDashboard_Success() throws Exception {
        mockMvc.perform(get("/api/auth/admin"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to Admin Dashboard!"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    // ========== KEYCLOAK CONFIG TESTS ==========

    @Test
    void getKeycloakConfig_Success() throws Exception {
        mockMvc.perform(get("/api/auth/keycloak-config"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url").value("http://localhost:8080"))
                .andExpect(jsonPath("$.realm").value("friendly-housing"))
                .andExpect(jsonPath("$.clientId").value("friendly-housing-frontend"))
                .andExpect(jsonPath("$.tokenUrl").exists());
    }

    // ========== HEALTH CHECK TESTS ==========

    @Test
    void healthCheck_Success() throws Exception {
        mockMvc.perform(get("/api/auth/health"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("user-service"))
                .andExpect(jsonPath("$.keycloakUrl").value("http://localhost:8080"))
                .andExpect(jsonPath("$.realm").value("friendly-housing"));
    }

    // ========== TOKEN INFO TESTS ==========

    @Test
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void getTokenInfo_WithoutJwt() throws Exception {
        // WithMockUser doesn't provide JWT, so this will return an error
        mockMvc.perform(get("/api/auth/token-info"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid token"));
    }

    // ========== LOGOUT TESTS ==========

    @Test
    void logout_Success() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logout from Keycloak"))
                .andExpect(jsonPath("$.logoutUrl").exists());
    }
}