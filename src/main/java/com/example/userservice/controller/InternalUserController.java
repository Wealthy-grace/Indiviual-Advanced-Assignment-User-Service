package com.example.userservice.controller;

import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.domain.dto.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/internal/users")
@RequiredArgsConstructor
@Slf4j
public class InternalUserController {

    private final UserService userService;

    /**
     * Get user by username - for internal service calls only
     */
    @GetMapping("/username/{username}")
    public ResponseEntity<?> getUserByUsernameInternal(@PathVariable String username) {
        log.info("Internal request to get user by username: {}", username);

        try {
            UserDto user = userService.getUserByUsername(username);
            if (user == null) {
                log.warn("User not found with username: {}", username);
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }

            log.info("Successfully retrieved user: {}", username);
            return new ResponseEntity<>(user, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving user by username {}: {}", username, e.getMessage());
            ErrorResponse errorResponse = new ErrorResponse("Internal error", "Failed to retrieve user");
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get user by ID - for internal service calls only
     */
    @GetMapping("/id/{id}")
    public ResponseEntity<?> getUserByIdInternal(@PathVariable Long id) {
        log.info("Internal request to get user by ID: {}", id);

        try {
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

    /**
     * Get user role by username - for internal service calls only
     */
    @GetMapping("/username/{username}/role")
    public ResponseEntity<?> getUserRoleByUsernameInternal(@PathVariable String username) {
        log.info("Internal request to get user role by username: {}", username);

        try {
            String role = String.valueOf(userService.getUserRole(username));
            RoleResponse roleResponse = new RoleResponse(role);
            return new ResponseEntity<>(roleResponse, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving user role for username {}: {}", username, e.getMessage());
            ErrorResponse errorResponse = new ErrorResponse("User not found", e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Get user role by ID - for internal service calls only
     */
    @GetMapping("/id/{id}/role")
    public ResponseEntity<?> getUserRoleByIdInternal(@PathVariable Long id) {
        log.info("Internal request to get user role by ID: {}", id);

        try {
            String role = String.valueOf(userService.getUserRole(id));
            RoleResponse roleResponse = new RoleResponse(role);
            return new ResponseEntity<>(roleResponse, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving user role for ID {}: {}", id, e.getMessage());
            ErrorResponse errorResponse = new ErrorResponse("User not found", e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Check if user exists by username - for internal service calls only
     */
    @GetMapping("/username/{username}/exists")
    public ResponseEntity<Boolean> userExistsByUsername(@PathVariable String username) {
        log.info("Internal request to check if user exists: {}", username);

        try {
            UserDto user = userService.getUserByUsername(username);
            boolean exists = user != null;
            log.info("User existence check for {}: {}", username, exists);
            return new ResponseEntity<>(exists, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error checking user existence for {}: {}", username, e.getMessage());
            return new ResponseEntity<>(false, HttpStatus.OK);
        }
    }

    /**
     * Health check endpoint for internal services
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return new ResponseEntity<>("Internal User Service is healthy", HttpStatus.OK);
    }

    // Response DTOs
    static class ErrorResponse {
        private String error;
        private String message;

        public ErrorResponse(String error, String message) {
            this.error = error;
            this.message = message;
        }

        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }

    static class RoleResponse {
        private String role;

        public RoleResponse(String role) {
            this.role = role;
        }

        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }
}