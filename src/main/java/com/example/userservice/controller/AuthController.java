package com.example.userservice.controller;

import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.configuration.exceptions.UserAlreadyExistsException;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;

    @Value("${keycloak.auth-server-url:http://localhost:8080}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm:friendly-housing}")
    private String keycloakRealm;

    // ========== PUBLIC ENDPOINTS (NO AUTH REQUIRED) ==========

    /**
     * Register new user - creates user in both Keycloak and local database
     * <p>
     * PUBLIC - No authentication required
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest request) {
        try {
            log.info("Signup request for username: {}", request.getUsername());

            SignUpResponse response = userService.createUser(request);

            log.info("User successfully registered: {}", request.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (UserAlreadyExistsException e) {
            log.warn("User already exists: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    new ErrorResponse("User already exists", e.getMessage()));

        } catch (Exception e) {
            log.error("Signup error for {}: {}", request.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Signup failed", "Failed to create user: " + e.getMessage()));
        }
    }

    /**
     * Login endpoint - directs to Keycloak authentication
     * <p>
     * PUBLIC - No authentication required
     * This endpoint just provides Keycloak token URL information
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest request) {
        try {
            log.info("Login request for username: {}", request.getUsername());

            LonginResponse response = userService.Login(request);

            // Add Keycloak token URL
            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("message", response.getMessage());
            responseMap.put("user", response.getUser());
            responseMap.put("keycloakTokenUrl", String.format("%s/realms/%s/protocol/openid-connect/token",
                    keycloakServerUrl, keycloakRealm));
            responseMap.put("instructions", "Use POST request to keycloakTokenUrl with username and password to get token");

            return ResponseEntity.ok(responseMap);

        } catch (RuntimeException e) {
            log.warn("Login attempt failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ErrorResponse("Login failed", e.getMessage()));
        }
    }

    /**
     * Get user by username - PUBLIC endpoint for now
     * <p>
     * Consider adding @PreAuthorize if you want to restrict this
     */
    @GetMapping("/user/{username}")
    public ResponseEntity<?> getUser(@PathVariable String username) {
        try {
            log.info("Fetching user: {}", username);

            UserDto user = userService.getUserByUsername(username);

            if (user == null) {
                log.warn("User not found: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        new ErrorResponse("User not found", "No user with username: " + username));
            }

            return ResponseEntity.ok(user);

        } catch (Exception e) {
            log.error("Error fetching user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Error", "Failed to fetch user: " + e.getMessage()));
        }
    }

    /**
     * Keycloak configuration endpoint
     * <p>
     * PUBLIC - Provides frontend configuration
     */
    @GetMapping("/keycloak-config")
    public ResponseEntity<?> getKeycloakConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("url", keycloakServerUrl);
        config.put("realm", keycloakRealm);
        config.put("clientId", "friendly-housing-frontend");
        config.put("tokenUrl", String.format("%s/realms/%s/protocol/openid-connect/token",
                keycloakServerUrl, keycloakRealm));

        return ResponseEntity.ok(config);
    }

    /**
     * Health check endpoint
     * <p>
     * PUBLIC - For monitoring
     */
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "user-service");
        health.put("keycloakUrl", keycloakServerUrl);
        health.put("realm", keycloakRealm);

        return ResponseEntity.ok(health);
    }

    // ========== AUTHENTICATED ENDPOINTS (ANY AUTHENTICATED USER) ==========

    /**
     * Get current user profile - requires authentication
     * <p>
     * ANY authenticated user can access their own profile
     */
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        try {
            // Get authenticated user from JWT token
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                        new ErrorResponse("Unauthorized", "User not authenticated"));
            }

            // Extract username from JWT (case-insensitive)
            String username = getUsernameFromAuthentication(authentication);

            log.info("Profile request for user: {}", username);

            // Get user profile from database (case-insensitive lookup)
            UserDto userProfile = userService.getUserProfile(username.toLowerCase());

            // Add JWT claims to response
            Map<String, Object> response = new HashMap<>();
            response.put("user", userProfile);
            response.put("roles", authentication.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.toList()));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error getting profile: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Error", "Failed to get profile: " + e.getMessage()));
        }
    }

    /**
     * Update user profile - requires authentication
     * <p>
     * Users can only update their own profile
     */
    @PreAuthorize("isAuthenticated()")
    @PutMapping("/profile")
    public ResponseEntity<?> updateUserProfile(@Valid @RequestBody UserDto userDto) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = getUsernameFromAuthentication(authentication);

            log.info("Profile update request from user: {}", username);

            // Get current user to ensure they can only update their own profile
            UserDto currentUser = userService.getUserByUsername(username.toLowerCase());

            if (currentUser == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        new ErrorResponse("User not found", "User profile not found"));
            }

            // Users can only update their own profile (unless they're admin)
            boolean isAdmin = hasRole(authentication, "ROLE_ADMIN");
            if (!currentUser.getId().equals(userDto.getId()) && !isAdmin) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                        new ErrorResponse("Forbidden", "You can only update your own profile"));
            }

            // Update the profile
            UserDto updatedUser = userService.updateUser(userDto);

            log.info("Profile updated successfully for user: {}", username);
            return ResponseEntity.ok(updatedUser);

        } catch (Exception e) {
            log.error("Error updating profile: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Update failed", e.getMessage()));
        }
    }

    /**
     * Get JWT token information - for debugging
     * <p>
     * ANY authenticated user can see their token info
     */
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/token-info")
    public ResponseEntity<?> getTokenInfo() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication.getPrincipal() instanceof Jwt) {
                Jwt jwt = (Jwt) authentication.getPrincipal();

                Map<String, Object> tokenInfo = new HashMap<>();
                tokenInfo.put("subject", jwt.getSubject());
                tokenInfo.put("username", jwt.getClaimAsString("preferred_username"));
                tokenInfo.put("email", jwt.getClaimAsString("email"));
                tokenInfo.put("name", jwt.getClaimAsString("name"));
                tokenInfo.put("roles", authentication.getAuthorities().stream()
                        .map(auth -> auth.getAuthority())
                        .collect(Collectors.toList()));
                tokenInfo.put("issuedAt", jwt.getIssuedAt());
                tokenInfo.put("expiresAt", jwt.getExpiresAt());
                tokenInfo.put("issuer", jwt.getIssuer());

                return ResponseEntity.ok(tokenInfo);
            }

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    new ErrorResponse("Invalid token", "Token information not available"));

        } catch (Exception e) {
            log.error("Error getting token info: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Error", e.getMessage()));
        }
    }

    /**
     * Logout endpoint - provides information about logout
     * <p>
     * PUBLIC - just provides logout URL
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        String logoutUrl = String.format("%s/realms/%s/protocol/openid-connect/logout",
                keycloakServerUrl, keycloakRealm);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Logout from Keycloak");
        response.put("logoutUrl", logoutUrl);

        return ResponseEntity.ok(response);
    }

    // ========== ROLE-BASED ENDPOINTS ==========

    /**
     * User dashboard endpoint
     * <p>
     * Requires: ROLE_STUDENT, ROLE_CARRIER_WORKER, or ROLE_PROPERTY_MANAGER
     */
    @PreAuthorize("hasAnyRole('ROLE_STUDENT', 'ROLE_CARRIER_WORKER', 'ROLE_PROPERTY_MANAGER')")
    @GetMapping("/user/dashboard")
    public ResponseEntity<?> userDashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = getUsernameFromAuthentication(authentication);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to your dashboard!");
        response.put("username", username);
        response.put("roles", getRolesFromAuthentication(authentication));

        return ResponseEntity.ok(response);
    }

    /**
     * Get user role by username
     * <p>
     * Requires: ROLE_ADMIN or ROLE_PROPERTY_MANAGER
     */
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_PROPERTY_MANAGER')")
    @GetMapping("/user/{username}/role")
    public ResponseEntity<?> getUserRole(@PathVariable String username) {
        try {
            log.info("Role request for user: {}", username);

            String role = String.valueOf(userService.getUserRole(username.toLowerCase()));
            return ResponseEntity.ok(new RoleResponse(role));

        } catch (Exception e) {
            log.error("Error getting role for {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", e.getMessage()));
        }
    }

    /**
     * Get user role by ID
     * <p>
     * Requires: ROLE_ADMIN or ROLE_PROPERTY_MANAGER
     */
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_PROPERTY_MANAGER')")
    @GetMapping("/user/id/{id}/role")
    public ResponseEntity<?> getUserRoleById(@PathVariable Long id) {
        try {
            log.info("Role request for user ID: {}", id);

            String role = String.valueOf(userService.getUserRole(id));
            return ResponseEntity.ok(new RoleResponse(role));

        } catch (Exception e) {
            log.error("Error getting role for user ID {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", e.getMessage()));
        }
    }

    // ========== ADMIN ONLY ENDPOINTS ==========

    /**
     * Get all users
     * <p>
     * Requires: ROLE_ADMIN only
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        try {
            log.info("Fetching all users");

            List<UserDto> users = userService.getAllUsers();

            log.info("Retrieved {} users", users.size());
            return ResponseEntity.ok(users);

        } catch (Exception e) {
            log.error("Error fetching all users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Error", "Failed to fetch users: " + e.getMessage()));
        }
    }

   // Admin Get User By ID cd
   // Line 393-413
   @PreAuthorize("hasRole('ROLE_ADMIN')")
   @GetMapping("/user/id/{id}")  // ✅ Changed from /user/{id}
   public ResponseEntity<?> getUserById(@PathVariable Long id) {
       try {
           log.info("Fetching user by ID: {}", id);
           UserDto user = userService.getUserById(id);
           if (user == null) {
               log.warn("User not found with ID: {}", id);
               return new ResponseEntity<>(HttpStatus.NOT_FOUND);
           }

           log.info("Successfully retrieved user with ID: {}", id);
           return new ResponseEntity<>(user, HttpStatus.OK);

       } catch (Exception e) {
           log.error("Error retrieving user by ID {}: {}", id, e.getMessage());
           ErrorResponse errorResponse = new ErrorResponse("Internal error", "Failed to retrieve user");
           return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
       }
   }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            log.info("Delete request for user ID: {}", id);

            userService.deleteUser(id);

            log.info("User deleted successfully: {}", id);
            return ResponseEntity.ok(new SuccessResponse("User deleted successfully"));

        } catch (Exception e) {
            log.error("Error deleting user {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ErrorResponse("Delete failed", e.getMessage()));
        }
    }

    /**
     * Admin dashboard endpoint
     * <p>
     * Requires: ROLE_ADMIN only
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<?> adminDashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = getUsernameFromAuthentication(authentication);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to Admin Dashboard!");
        response.put("username", username);
        response.put("roles", getRolesFromAuthentication(authentication));

        return ResponseEntity.ok(response);
    }

    // ========== HELPER METHODS ==========

    /**
     * Extract username from JWT token
     * Tries multiple claims to find username
     */
    private String getUsernameFromAuthentication(Authentication authentication) {
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            // Try to get username from preferred_username claim (Keycloak default)
            String username = jwt.getClaimAsString("preferred_username");

            // Fallback to sub claim if preferred_username is not present
            if (username == null || username.isEmpty()) {
                username = jwt.getClaimAsString("sub");
            }

            // Fallback to name claim
            if (username == null || username.isEmpty()) {
                username = jwt.getClaimAsString("name");
            }

            return username;
        }

        // Fallback to authentication name
        return authentication.getName();
    }

    /**
     * Extract user ID from JWT token
     */
    private String getUserIdFromAuthentication(Authentication authentication) {
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            return jwt.getClaimAsString("sub");
        }
        return null;
    }

    /**
     * Check if user has specific role
     */
    private boolean hasRole(Authentication authentication, String role) {
        return authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals(role));
    }

    /**
     * Get all roles from authentication
     */
    private List<String> getRolesFromAuthentication(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.toList());
    }

    // ========== RESPONSE DTOs ==========

    /**
     * Error response DTO
     */
    public record ErrorResponse(String error, String message) {
    }

    /**
     * Role response DTO
     */
    public record RoleResponse(String role) {
    }

    /**
     * Success response DTO
     */
    public record SuccessResponse(String message) {
    }
}