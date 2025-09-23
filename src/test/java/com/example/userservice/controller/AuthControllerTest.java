package com.example.userservice.controller;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import com.example.userservice.persistence.entity.Role;
import com.example.userservice.security.Config.UnauthorizedDataAccessException;
import com.example.userservice.security.jwt.JwtUtils;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@AutoConfigureMockMvc(addFilters = false)
@WebMvcTest(AuthController.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    private SignUpRequest signUpRequest;
    private LoginRequest loginRequest;
    private UserDto userDto;
    private SignUpResponse signUpResponse;
    private LonginResponse loginResponse;

    // Provide all required beans as mocks for context startup


    @TestConfiguration
    static class ControllerMockConfig {
        @Bean
        public UserService userService() {
            return Mockito.mock(UserService.class);
        }
        @Bean
        public AuthenticationManager authenticationManager() {
            return Mockito.mock(AuthenticationManager.class);
        }
        @Bean
        public PasswordEncoder passwordEncoder() {
            return Mockito.mock(PasswordEncoder.class);
        }
        @Bean
        public JwtUtils jwtUtils() {
            return Mockito.mock(JwtUtils.class);
        }
        @Bean
        public UserDetailsService userDetailsService() {
            return Mockito.mock(UserDetailsService.class);
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
                .role(Role.ROLE_STUDENT)
                .image("https://example.com/image.jpg") // required image field
                .build();

        loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();

        userDto = UserDto.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role("ROLE_STUDENT")
                .image("https://example.com/image.jpg")
                .password("Password@123")
                .token("jwt-token")
                .build();

        signUpResponse = SignUpResponse.builder()
                .message("User created successfully")
                .user(userDto)
                .build();

        loginResponse = new LonginResponse();
        loginResponse.setMessage("Login successful");
        loginResponse.setUser(userDto);
        loginResponse.setToken("jwt-token");
    }

    @Test
    void registerUser_Success() throws Exception {
        when(userService.createUser(any(SignUpRequest.class))).thenReturn(signUpResponse);

        mockMvc.perform(post("/api/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User created successfully"))
                .andExpect(jsonPath("$.user.username").value("testuser"));
    }

    @Test
    void loginUser_Success() throws Exception {
        when(userService.Login(any(LoginRequest.class))).thenReturn(loginResponse);

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.token").value("jwt-token"));
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
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

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
    @WithMockUser(username = "testuser", roles = {"STUDENT"})
    void getUserProfile_Success() throws Exception {
        when(userService.getUserProfile("testuser")).thenReturn(userDto);

        mockMvc.perform(get("/api/auth/profile"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    @WithMockUser(username = "nonexistent", roles = {"STUDENT"})
    void getUserProfile_UserNotFound() throws Exception {
        when(userService.getUserProfile("nonexistent"))
                .thenThrow(new RuntimeException("User not found"));

        mockMvc.perform(get("/api/auth/profile"))
                .andDo(print())
                .andExpect(status().isNotFound());
    }

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
     @WithMockUser(roles = {"STUDENT"})
    void getAllUsers_Failure() throws Exception {
        when(userService.getAllUsers())
                .thenThrow(new RuntimeException("Failed to retrieve users"));

        mockMvc.perform(get("/api/auth/users"))
                .andDo(print())
                .andExpect(status().isInternalServerError());
    }



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
                .andExpect(status().isNotFound());
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
        when(userService.getUserByUsername("nonexistent")).thenReturn(null);

        mockMvc.perform(put("/api/auth/profile")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userDto)))
                .andDo(print())
                .andExpect(status().isNotFound());
    }

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
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = {"STUDENT"})
    void userEndpoint_Success() throws Exception {
        mockMvc.perform(get("/api/auth/user"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, User! welcome to Dashboard for Appointment!"));
    }

    @Test
    @WithMockUser(roles = {"ADMIN"})
    void adminEndpoint_Success() throws Exception {
        mockMvc.perform(get("/api/auth/admin"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("congratulations, welcome Admin to Spring Security!"));
    }



    @Test
    @WithMockUser(roles = {"ADMIN"})
    void adminEndpoint_Authorized() throws Exception {
        mockMvc.perform(get("/api/auth/admin"))
                .andDo(print())
                .andExpect(status().isOk());
    }


}
