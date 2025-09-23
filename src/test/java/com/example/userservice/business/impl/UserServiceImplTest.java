package com.example.userservice.business.impl;

import com.example.userservice.business.Converter.UserConverDto;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class UserServiceImplTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepo userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserConverDto userConverDto;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private UserServiceImpl userService;

    private SignUpRequest signUpRequest;
    private UserEntity userEntity;
    private UserDto userDto;
    private LoginRequest loginRequest;


//    @BeforeEach
//    void setUp() {
//        MockitoAnnotations.openMocks(this);
//    }

    @BeforeEach
    void setUp() {


        signUpRequest = SignUpRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password123")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role(Role.valueOf("ROLE_STUDENT"))
                .build();

        userEntity = UserEntity.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role(Role.valueOf("ROLE_STUDENT"))
                .build();

        userDto = UserDto.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .fullName("Test User")
                .telephone("0612345678")
                .address("Test Address")
                .role("ROLE_STUDENT")
                .build();

        loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();




    }






    @Test
    void createUser_Success() {
        // Arrange
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByAddress(anyString())).thenReturn(false);
        when(userRepository.existsByFullName(anyString())).thenReturn(false);
        when(userRepository.existsByTelephone(anyString())).thenReturn(false);
        when(userConverDto.mapToEntity(signUpRequest)).thenReturn(userEntity);
        when(userRepository.save(userEntity)).thenReturn(userEntity);
        when(userConverDto.mapToDTO(userEntity)).thenReturn(userDto);

        // Act
        SignUpResponse response = userService.createUser(signUpRequest);

        // Assert
        assertNotNull(response);
        assertEquals("User created successfully", response.getMessage());
        assertEquals(userDto, response.getUser());
        verify(userRepository).save(userEntity);
    }

    @Test
    void createUser_UsernameAlreadyExists_ThrowsException() {
        // Arrange
        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        // Act & Assert
        UserAlreadyExistsException exception = assertThrows(
                UserAlreadyExistsException.class,
                () -> userService.createUser(signUpRequest)
        );
        assertEquals("Username already exists: testuser", exception.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void createUser_EmailAlreadyExists_ThrowsException() {
        // Arrange
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        // Act & Assert
        UserAlreadyExistsException exception = assertThrows(
                UserAlreadyExistsException.class,
                () -> userService.createUser(signUpRequest)
        );
        assertEquals("Email already exists: test@example.com", exception.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void login_Success() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(userEntity));
        when(jwtUtils.generateTokenFromUsername("testuser")).thenReturn("jwt-token");

        // Act
        LonginResponse response = userService.Login(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals("Congratulations, you have successfully logged in!", response.getMessage());
        assertEquals("jwt-token", response.getToken());
        assertNotNull(response.getUser());
    }

    @Test
    void login_BadCredentials_ThrowsException() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.Login(loginRequest)
        );
        assertEquals("Invalid username or password", exception.getMessage());
    }

    @Test
    void login_UserNotFoundAfterAuth_ThrowsException() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.Login(loginRequest)
        );
        assertEquals("Login failed: User not found after authentication", exception.getMessage());
    }


    @Test
    void getUserByUsername_UserExists_ReturnsUserDto_ServiceTest() {
        // Arrange
        String role = "ROLE_STUDENT"; // or ROLE_ADMIN depending on your test
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername("testuser");
        userEntity.setEmail("test@example.com");
        userEntity.setRole(Role.valueOf(role)); // important!

        // Mock repository
        when(userRepository.findAll()).thenReturn(Collections.singletonList(userEntity));

        // Act
        List<UserDto> users = userService.getAllUsers(); // internally converts entity to DTO

        // Assert
        assertNotNull(users);
        assertEquals(1, users.size());
        assertEquals("testuser", users.get(0).getUsername());
        assertEquals("ROLE_STUDENT", users.get(0).getRole());
    }



    @Test
    void getUserByUsername_UserNotExists_ReturnsNull() {
        // Arrange
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // Act
        UserDto result = userService.getUserByUsername("nonexistent");

        // Assert
        assertNull(result);
    }

    @Test
    void getUserById_UserExists_ReturnsUserDto() {
        // Arrange
        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity));

        // Act
        UserDto result = userService.getUserById(1L);

        // Assert
        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals("testuser", result.getUsername());
    }

    @Test
    void getUserById_UserNotExists_ReturnsNull() {
        // Arrange
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // Act
        UserDto result = userService.getUserById(999L);

        // Assert
        assertNull(result);
    }

    @Test
    void getUserProfile_UserExists_ReturnsUserDto() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(userEntity));

        // Act
        UserDto result = userService.getUserProfile("testuser");

        // Assert
        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
    }

    @Test
    void getUserProfile_UserNotExists_ThrowsException() {
        // Arrange
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.getUserProfile("nonexistent")
        );
        assertEquals("User not found with username: nonexistent", exception.getMessage());
    }

    @Test
    void getAllUsers_ReturnsListOfUsers() {
        // Arrange
        UserEntity user1 = UserEntity.builder()
                .id(1L)
                .username("user1")
                .fullName("User One")
                .email("user1@example.com")
                .telephone("1234567890")
                .address("123 Main St")
                .image("image1.png")
                .role(Role.ROLE_STUDENT) // ✅ correct enum
                .build();

        UserEntity user2 = UserEntity.builder()
                .id(2L)
                .username("user2")
                .fullName("User Two")
                .email("user2@example.com")
                .telephone("0987654321")
                .address("456 Elm St")
                .image("image2.png")
                .role(Role.ROLE_ADMIN) // ✅ correct enum
                .build();

        List<UserEntity> userEntities = Arrays.asList(user1, user2);

        // Mock repository
        when(userRepository.findAll()).thenReturn(userEntities);

        // Act
        List<UserDto> result = userService.getAllUsers();

        // Assert
        assertNotNull(result);
        assertEquals(2, result.size());

        // Validate first user
        UserDto dto1 = result.get(0);
        assertEquals(user1.getId(), dto1.getId());
        assertEquals(user1.getUsername(), dto1.getUsername());
        assertEquals(user1.getEmail(), dto1.getEmail());
        assertEquals("ROLE_STUDENT", dto1.getRole()); // ✅ String in DTO

        // Validate second user
        UserDto dto2 = result.get(1);
        assertEquals(user2.getId(), dto2.getId());
        assertEquals(user2.getUsername(), dto2.getUsername());
        assertEquals(user2.getEmail(), dto2.getEmail());
        assertEquals("ROLE_ADMIN", dto2.getRole()); // ✅ String in DTO
    }

    @Test
    void getUserRole_ByUsername_UserExists_ReturnsRole() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(userEntity));

        // Act
        String result = String.valueOf(userService.getUserRole("testuser"));

        // Assert
        assertEquals("ROLE_STUDENT", result);
    }

    @Test
    void getUserRole_ByUsername_UserNotExists_ThrowsException() {
        // Arrange
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.getUserRole("nonexistent")
        );
        assertEquals("User not found with username: nonexistent", exception.getMessage());
    }

    @Test
    void getUserRole_ById_UserExists_ReturnsRole() {
        // Arrange
        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity));

        // Act
        String result = String.valueOf(userService.getUserRole(1L));

        // Assert
        assertEquals("ROLE_STUDENT", result);
    }

    @Test
    void getUserRole_ById_UserNotExists_ThrowsException() {
        // Arrange
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.getUserRole(999L)
        );
        assertEquals("User not found with ID: 999", exception.getMessage());
    }

    @Test
    void updateUser_UserExists_ReturnsUpdatedUser() {
        // Arrange
        UserDto updateDto = UserDto.builder()
                .id(1L)
                .username("updateduser")
                .email("updated@example.com")
                .fullName("Updated User")
                .telephone("0687654321")
                .address("Updated Address")
                .build();

        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity));
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);

        // Act
        UserDto result = userService.updateUser(updateDto);

        // Assert
        assertNotNull(result);
        verify(userRepository).save(any(UserEntity.class));
    }

    @Test
    void updateUser_UserNotExists_ThrowsException() {
        // Arrange
        UserDto updateDto = UserDto.builder().id(999L).build();
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.updateUser(updateDto)
        );
        assertEquals("User not found with ID: 999", exception.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void deleteUser_UserExists_DeletesUser() {
        // Arrange
        when(userRepository.existsById(1L)).thenReturn(true);

        // Act
        userService.deleteUser(1L);

        // Assert
        verify(userRepository).deleteById(1L);
    }

    @Test
    void deleteUser_UserNotExists_ThrowsException() {
        // Arrange
        when(userRepository.existsById(999L)).thenReturn(false);

        // Act & Assert
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> userService.deleteUser(999L)
        );
        assertEquals("User not found with ID: 999", exception.getMessage());
        verify(userRepository, never()).deleteById(any());
    }
}