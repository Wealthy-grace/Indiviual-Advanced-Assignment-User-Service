package com.example.userservice.controller;

import com.example.userservice.business.interfaces.UserService;
import com.example.userservice.domain.dto.UserDto;
import com.example.userservice.domain.request.LoginRequest;
import com.example.userservice.domain.request.SignUpRequest;
import com.example.userservice.domain.response.LonginResponse;
import com.example.userservice.domain.response.SignUpResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponse> registerUser(@Valid @RequestBody SignUpRequest request) {
        SignUpResponse response = userService.createUser(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LonginResponse> loginUser(@Valid @RequestBody LoginRequest request) {
        try {
            LonginResponse response = userService.Login(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            // Return an unauthorized response with an optional message
            LonginResponse errorResponse = new LonginResponse();
            errorResponse.setUser(null);
            errorResponse.setToken(null);
            errorResponse.setMessage("Invalid username or password");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<?> getUser(@PathVariable String username) {
        UserDto user = userService.getUserByUsername(username);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", "No user with username: " + username));
        }
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasRole('ROLE_STUDENT') or hasRole('ROLE_ADMIN') or hasRole('ROLE_CARRIER_WORKER') or hasRole('ROLE_PROPERTY_MANAGER')")
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        try {
            // Get the currently authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();

            UserDto userProfile = userService.getUserProfile(username);
            return ResponseEntity.ok(userProfile);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", e.getMessage()));
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        List<UserDto> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_PROPERTY_MANAGER')")
    @GetMapping("/user/{username}/role")
    public ResponseEntity<?> getUserRole(@PathVariable String username) {
        try {
            String role = String.valueOf(userService.getUserRole(username));
            return ResponseEntity.ok(new RoleResponse(role));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", e.getMessage()));
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_PROPERTY-MANAGER')")
    @GetMapping("/user/id/{id}/role")
    public ResponseEntity<?> getUserRoleById(@PathVariable Long id) {
        try {
            String role = String.valueOf(userService.getUserRole(id));
            return ResponseEntity.ok(new RoleResponse(role));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("User not found", e.getMessage()));
        }
    }

    @PreAuthorize("hasRole('ROLE_STUDENT') or hasRole('ROLE_ADMIN') or hasRole('ROLE_CARRIER_WORKER') or hasRole('ROLE_PROPERTY-MANAGER')")
    @PutMapping("/profile")
    public ResponseEntity<?> updateUserProfile(@Valid @RequestBody UserDto userDto) {
        try {
            // Get the currently authenticated user's username
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();

            // Get current user to ensure they can only update their own profile
            UserDto currentUser = userService.getUserByUsername(username);
            if (currentUser == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                        new ErrorResponse("User not found", "Current user not found"));
            }

            // Set the ID to ensure updating the correct user
            userDto.setId(currentUser.getId());

            UserDto updatedUser = userService.updateUser(userDto);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                    new ErrorResponse("Update failed", e.getMessage()));
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            userService.deleteUser(id);
            return ResponseEntity.ok(new SuccessResponse("User deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    new ErrorResponse("Delete failed", e.getMessage()));
        }
    }

    @PreAuthorize("hasRole('ROLE_STUDENT')  or hasRole('ROLE_CARRIER_WORKER') or hasRole('ROLE_PROPERTY-MANAGER')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello, User! welcome to Dashboard for Appointment!";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "congratulations, welcome Admin to Spring Security!";
    }




    // Response DTOs
    record ErrorResponse(String error, String message) {}
    record RoleResponse(String role) {}
    record SuccessResponse(String message) {}
}