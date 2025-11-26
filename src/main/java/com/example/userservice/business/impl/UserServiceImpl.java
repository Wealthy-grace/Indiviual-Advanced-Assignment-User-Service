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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepo userRepository;
    private final UserConverDto userConverDto;
    private final KeycloakUserService keycloakUserService;

    /**
     * Creates a new user in both Keycloak and local database.
     *
     * Flow:
     * 1. Validate request and check for duplicates in local DB
     * 2. Check if user exists in Keycloak
     * 3. Create user in Keycloak FIRST (to get Keycloak ID)
     * 4. Save user in local database with Keycloak ID
     * 5. Rollback if any step fails
     *
     * @param signUpRequest User signup details
     * @return SignUpResponse with created user info
     * @throws UserAlreadyExistsException if user already exists
     * @throws RuntimeException if creation fails
     */
    @Override
    @Transactional
    public SignUpResponse createUser(SignUpRequest signUpRequest) {
        log.info("🔵 Starting user creation process for: {}", signUpRequest.getUsername());

        // ✅ Step 1: Validate and check if user exists in LOCAL database
        validateAndCheckLocalDuplicates(signUpRequest);
        log.debug("✅ Local database validation passed");

        // ✅ Step 2: Check if user exists in KEYCLOAK
        checkKeycloakUserExists(signUpRequest.getUsername());
        log.debug("✅ Keycloak validation passed");

        // Extract names for Keycloak
        String[] names = signUpRequest.getFullName().split(" ", 2);
        String firstName = names[0];
        String lastName = names.length > 1 ? names[1] : "";

        String keycloakUserId = null;

        try {
            // ✅ Step 3: Create user in Keycloak FIRST
            log.debug("📤 Attempting to create user in Keycloak: {}", signUpRequest.getUsername());

            keycloakUserId = keycloakUserService.createKeycloakUser(
                    signUpRequest.getUsername(),
                    signUpRequest.getEmail(),
                    signUpRequest.getPassword(),
                    firstName,
                    lastName,
                    signUpRequest.getRole() != null ? Role.valueOf(signUpRequest.getRole()) : Role.ROLE_STUDENT
            );

            log.info("✅ User successfully created in Keycloak with ID: {}", keycloakUserId);

            // ✅ Step 4: Create user entity for local database
            UserEntity user = userConverDto.mapToEntity(signUpRequest);
            user.setKeycloakId(keycloakUserId);

            // ✅ Step 5: Save user in local database
            userRepository.save(user);
            log.info("✅ User successfully created in local database: {}", signUpRequest.getUsername());

            return SignUpResponse.builder()
                    .message("User created successfully. You can now login with Keycloak.")
                    .user(userConverDto.mapToDTO(user))
                    .build();

        } catch (RuntimeException e) {
            log.error("❌ Error creating user {}: {}", signUpRequest.getUsername(), e.getMessage(), e);

            // If user was created in Keycloak but local DB save failed, rollback Keycloak user
            if (keycloakUserId != null) {
                try {
                    log.warn("🔄 Rolling back Keycloak user creation: {}", keycloakUserId);
                    keycloakUserService.deleteKeycloakUser(keycloakUserId);
                    log.info("✅ Keycloak user rollback successful");
                } catch (Exception rollbackException) {
                    log.error("❌ Failed to rollback Keycloak user {}: {}",
                            keycloakUserId, rollbackException.getMessage());
                }
            }

            // Check if it's a Keycloak 409 conflict or 403 Forbidden
            String errorMessage = e.getMessage().toLowerCase();

            if (errorMessage.contains("409") || errorMessage.contains("conflict")) {
                throw new UserAlreadyExistsException(
                        "User '" + signUpRequest.getUsername() + "' already exists in Keycloak. " +
                                "Please use a different username."
                );
            }

            if (errorMessage.contains("403") || errorMessage.contains("forbidden")) {
                throw new RuntimeException(
                        "Permission denied: Your application doesn't have permission to create users in Keycloak. " +
                                "Please ensure the 'user-service' client has 'Service accounts roles' enabled and " +
                                "the service account has 'manage-users' role from 'realm-management'.",
                        e
                );
            }

            throw new RuntimeException("Failed to create user: " + e.getMessage(), e);
        }
    }

    @Override
    public LonginResponse Login(LoginRequest loginRequest) {
        log.info("🔵 Login request for user: {}", loginRequest.getUsername());

        try {
            // Get user from database to verify existence
            UserEntity user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found: " + loginRequest.getUsername()));

            // Convert to DTO
            UserDto userDto = UserDto.fromEntity(user);

            // Return response with message about Keycloak
            LonginResponse response = new LonginResponse();
            response.setMessage("Please authenticate via Keycloak to get your access token. " +
                    "Use POST http://localhost:8080/realms/friendly-housing/protocol/openid-connect/token");
            response.setUser(userDto);
            response.setToken(null); // Token comes from Keycloak

            log.info("✅ Login info provided for user: {}", loginRequest.getUsername());

            return response;

        } catch (Exception e) {
            log.error("❌ Login request failed for user {}: {}", loginRequest.getUsername(), e.getMessage());
            throw new RuntimeException("Login failed: " + e.getMessage(), e);
        }
    }

    @Override
    public UserDto getUserByUsername(String username) {
        log.debug("🔍 Fetching user by username: {}", username);
        return userRepository.findByUsername(username)
                .map(userConverDto::mapToDTO)
                .orElse(null);
    }

    @Override
    public UserDto getUserById(Long id) {
        log.debug("🔍 Fetching user by ID: {}", id);
        return userRepository.findById(id)
                .map(UserDto::fromEntity)
                .orElse(null);
    }

    @Override
    public UserDto getUserProfile(String username) {
        log.info("🔍 Fetching profile for user: {}", username);
        return userRepository.findByUsername(username)
                .map(UserDto::fromEntity)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    @Override
    public List<UserDto> getAllUsers() {
        log.info("🔍 Fetching all users");
        List<UserEntity> users = userRepository.findAll();
        log.debug("Found {} users", users.size());
        return users.stream()
                .map(UserDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public Role getUserRole(String username) {
        log.debug("🔍 Fetching role for user: {}", username);
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
        return user.getRole();
    }

    @Override
    public Role getUserRole(Long id) {
        log.debug("🔍 Fetching role for user ID: {}", id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));
        return user.getRole();
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto) {
        log.info("🔵 Updating user: {}", userDto.getUsername());

        Optional<UserEntity> optionalUser = userRepository.findById(userDto.getId());
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("User not found with ID: " + userDto.getId());
        }

        UserEntity user = optionalUser.get();

        // Update local database
        user.setEmail(userDto.getEmail());
        user.setFullName(userDto.getFullName());
        user.setUsername(userDto.getUsername());
        user.setImage(userDto.getImage());
        user.setTelephone(userDto.getTelephone());
        user.setAddress(userDto.getAddress());

        userRepository.save(user);
        log.debug("✅ User updated in local database");

        // ✅ Update Keycloak if user has Keycloak ID
        if (user.getKeycloakId() != null && !user.getKeycloakId().isEmpty()) {
            try {
                String[] names = userDto.getFullName().split(" ", 2);
                String firstName = names[0];
                String lastName = names.length > 1 ? names[1] : "";

                keycloakUserService.updateKeycloakUser(
                        user.getKeycloakId(),
                        userDto.getEmail(),
                        firstName,
                        lastName
                );

                log.info("✅ User updated in Keycloak: {}", user.getKeycloakId());
            } catch (Exception e) {
                log.warn("⚠️ Failed to update user in Keycloak: {}", e.getMessage());
                // Continue anyway - local DB is updated
            }
        }

        log.info("✅ User updated successfully: {}", userDto.getUsername());

        return UserDto.fromEntity(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        log.info("🔵 Deleting user with ID: {}", id);

        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // ✅ Delete from Keycloak first (if exists)
        if (user.getKeycloakId() != null && !user.getKeycloakId().isEmpty()) {
            try {
                keycloakUserService.deleteKeycloakUser(user.getKeycloakId());
                log.info("✅ User deleted from Keycloak: {}", user.getKeycloakId());
            } catch (Exception e) {
                log.warn("⚠️ Failed to delete user from Keycloak: {}", e.getMessage());
                // Continue anyway to delete from local DB
            }
        }

        // Delete from local database
        userRepository.deleteById(id);

        log.info("✅ User deleted successfully from local database: {}", id);
    }

    /**
     * Validates signup request and checks if user already exists in LOCAL database.
     *
     * @param request SignUp request to validate
     * @throws UserAlreadyExistsException if user already exists
     */
    private void validateAndCheckLocalDuplicates(SignUpRequest request) {
        log.debug("🔍 Checking for duplicate users in local database");

        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("❌ Username already exists: {}", request.getUsername());
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("❌ Email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        // Only check optional fields if they are provided and not empty
        if (request.getAddress() != null && !request.getAddress().trim().isEmpty()
                && userRepository.existsByAddress(request.getAddress())) {
            log.warn("❌ Address already exists: {}", request.getAddress());
            throw new UserAlreadyExistsException("Address already exists: " + request.getAddress());
        }

        if (request.getFullName() != null && !request.getFullName().trim().isEmpty()
                && userRepository.existsByFullName(request.getFullName())) {
            log.warn("❌ Full name already exists: {}", request.getFullName());
            throw new UserAlreadyExistsException("Full name already exists: " + request.getFullName());
        }

        if (request.getTelephone() != null && !request.getTelephone().trim().isEmpty()
                && userRepository.existsByTelephone(request.getTelephone())) {
            log.warn("❌ Telephone already exists: {}", request.getTelephone());
            throw new UserAlreadyExistsException("Telephone already exists: " + request.getTelephone());
        }
    }

    /**
     * Checks if user already exists in Keycloak.
     *
     * @param username Username to check
     * @throws UserAlreadyExistsException if user exists in Keycloak
     */
    private void checkKeycloakUserExists(String username) {
        log.debug("🔍 Checking if user exists in Keycloak: {}", username);

        try {
            UserRepresentation existingKeycloakUser = keycloakUserService.getUserByUsername(username);
            if (existingKeycloakUser != null) {
                log.warn("❌ User already exists in Keycloak: {}", username);
                throw new UserAlreadyExistsException(
                        "User '" + username + "' already exists in Keycloak. " +
                                "Please use a different username or delete the existing user from Keycloak Admin Console."
                );
            }
        } catch (UserAlreadyExistsException e) {
            throw e; // Re-throw if it's already our exception
        } catch (Exception e) {
            log.debug("✅ User doesn't exist in Keycloak (or error checking): {}", e.getMessage());
            // Continue - user doesn't exist in Keycloak (or we couldn't check)
        }
    }
}