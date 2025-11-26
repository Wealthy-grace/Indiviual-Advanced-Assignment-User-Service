//package com.example.userservice.business.impl;
//
//import com.example.userservice.persistence.entity.Role;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.keycloak.admin.client.Keycloak;
//import org.keycloak.admin.client.resource.RealmResource;
//import org.keycloak.admin.client.resource.UsersResource;
//import org.keycloak.representations.idm.CredentialRepresentation;
//import org.keycloak.representations.idm.RoleRepresentation;
//import org.keycloak.representations.idm.UserRepresentation;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//// ✅ CORRECT IMPORT FOR SPRING BOOT 3.x
//import jakarta.ws.rs.core.Response;
//
//import java.net.URI;
//import java.util.Collections;
//import java.util.List;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class KeycloakUserService {
//
//    private final Keycloak keycloak;
//
//    @Value("${keycloak.realm}")
//    private String realm;
//
//    /**
//     * Create user in Keycloak
//     */
//    public String createKeycloakUser(String username, String email, String password,
//                                     String firstName, String lastName, Role role) {
//        try {
//            RealmResource realmResource = keycloak.realm(realm);
//            UsersResource usersResource = realmResource.users();
//
//            // Create user representation
//            UserRepresentation user = new UserRepresentation();
//            user.setUsername(username);
//            user.setEmail(email);
//            user.setFirstName(firstName);
//            user.setLastName(lastName);
//            user.setEnabled(true);
//            user.setEmailVerified(true);
//
//            // Create user in Keycloak
//            Response response = usersResource.create(user);
//
//            if (response.getStatus() != 201) {
//                String errorMessage = String.format("Failed to create user in Keycloak. Status: %d, Info: %s",
//                        response.getStatus(), response.getStatusInfo());
//                log.error(errorMessage);
//                response.close();
//                throw new RuntimeException(errorMessage);
//            }
//
//            // Extract user ID from location header
//            URI location = response.getLocation();
//            String locationPath = location.getPath();
//            String userId = locationPath.substring(locationPath.lastIndexOf('/') + 1);
//
//            response.close(); // ✅ Important: close the response
//
//            log.info("Created Keycloak user with ID: {}", userId);
//
//            // Set password
//            setUserPassword(userId, password);
//
//            // Assign role
//            assignRoleToUser(userId, role.name());
//
//            return userId;
//
//        } catch (Exception e) {
//            log.error("Error creating user in Keycloak: {}", e.getMessage(), e);
//            throw new RuntimeException("Failed to create user in Keycloak: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Set user password
//     */
//    private void setUserPassword(String userId, String password) {
//        try {
//            CredentialRepresentation credential = new CredentialRepresentation();
//            credential.setType(CredentialRepresentation.PASSWORD);
//            credential.setValue(password);
//            credential.setTemporary(false);
//
//            keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .resetPassword(credential);
//
//            log.info("Password set for Keycloak user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error setting password for user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to set password: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Assign role to user
//     */
//    public void assignRoleToUser(String userId, String roleName) {
//        try {
//            RealmResource realmResource = keycloak.realm(realm);
//
//            // Get role representation
//            RoleRepresentation role = realmResource.roles()
//                    .get(roleName)
//                    .toRepresentation();
//
//            // Assign role to user
//            realmResource.users()
//                    .get(userId)
//                    .roles()
//                    .realmLevel()
//                    .add(Collections.singletonList(role));
//
//            log.info("Assigned role {} to user {}", roleName, userId);
//
//        } catch (Exception e) {
//            log.error("Error assigning role {} to user {}: {}", roleName, userId, e.getMessage());
//            throw new RuntimeException("Failed to assign role: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Delete user from Keycloak
//     */
//    public void deleteKeycloakUser(String userId) {
//        try {
//            keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .remove();
//
//            log.info("Deleted Keycloak user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error deleting Keycloak user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to delete user from Keycloak", e);
//        }
//    }
//
//    /**
//     * Get user by username
//     */
//    public UserRepresentation getUserByUsername(String username) {
//        try {
//            List<UserRepresentation> users = keycloak.realm(realm)
//                    .users()
//                    .search(username, true); // exact match
//
//            if (users.isEmpty()) {
//                log.info("No user found with username: {}", username);
//                return null;
//            }
//
//            log.info("Found user with username: {}", username);
//            return users.get(0);
//
//        } catch (Exception e) {
//            log.error("Error getting user from Keycloak: {}", e.getMessage());
//            throw new RuntimeException("Failed to get user: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Get user by ID
//     */
//    public UserRepresentation getUserById(String userId) {
//        try {
//            UserRepresentation user = keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .toRepresentation();
//
//            log.info("Found user with ID: {}", userId);
//            return user;
//
//        } catch (Exception e) {
//            log.error("Error getting user by ID {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to get user by ID: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Update user in Keycloak
//     */
//    public void updateKeycloakUser(String userId, String email, String firstName, String lastName) {
//        try {
//            UsersResource usersResource = keycloak.realm(realm).users();
//            UserRepresentation user = usersResource.get(userId).toRepresentation();
//
//            // Update user fields
//            user.setEmail(email);
//            user.setFirstName(firstName);
//            user.setLastName(lastName);
//
//            // Save changes
//            usersResource.get(userId).update(user);
//
//            log.info("Updated Keycloak user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error updating Keycloak user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to update user in Keycloak: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Check if user exists by username
//     */
//    public boolean userExists(String username) {
//        try {
//            List<UserRepresentation> users = keycloak.realm(realm)
//                    .users()
//                    .search(username, true);
//
//            boolean exists = !users.isEmpty();
//            log.info("User existence check for {}: {}", username, exists);
//            return exists;
//
//        } catch (Exception e) {
//            log.error("Error checking user existence: {}", e.getMessage());
//            return false;
//        }
//    }
//
//    /**
//     * Update user password
//     */
//    public void updateUserPassword(String userId, String newPassword) {
//        try {
//            CredentialRepresentation credential = new CredentialRepresentation();
//            credential.setType(CredentialRepresentation.PASSWORD);
//            credential.setValue(newPassword);
//            credential.setTemporary(false);
//
//            keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .resetPassword(credential);
//
//            log.info("Password updated for Keycloak user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error updating password for user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to update password: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Enable or disable user account
//     */
//    public void setUserEnabled(String userId, boolean enabled) {
//        try {
//            UsersResource usersResource = keycloak.realm(realm).users();
//            UserRepresentation user = usersResource.get(userId).toRepresentation();
//
//            user.setEnabled(enabled);
//            usersResource.get(userId).update(user);
//
//            log.info("User {} enabled status set to: {}", userId, enabled);
//
//        } catch (Exception e) {
//            log.error("Error setting user enabled status: {}", e.getMessage());
//            throw new RuntimeException("Failed to set user enabled status: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Get user roles
//     */
//    public List<RoleRepresentation> getUserRoles(String userId) {
//        try {
//            List<RoleRepresentation> roles = keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .roles()
//                    .realmLevel()
//                    .listEffective();
//
//            log.info("Retrieved {} roles for user {}", roles.size(), userId);
//            return roles;
//
//        } catch (Exception e) {
//            log.error("Error getting roles for user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to get user roles: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Remove role from user
//     */
//    public void removeRoleFromUser(String userId, String roleName) {
//        try {
//            RealmResource realmResource = keycloak.realm(realm);
//
//            // Get role representation
//            RoleRepresentation role = realmResource.roles()
//                    .get(roleName)
//                    .toRepresentation();
//
//            // Remove role from user
//            realmResource.users()
//                    .get(userId)
//                    .roles()
//                    .realmLevel()
//                    .remove(Collections.singletonList(role));
//
//            log.info("Removed role {} from user {}", roleName, userId);
//
//        } catch (Exception e) {
//            log.error("Error removing role from user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to remove role: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Get all users from Keycloak
//     */
//    public List<UserRepresentation> getAllUsers() {
//        try {
//            List<UserRepresentation> users = keycloak.realm(realm)
//                    .users()
//                    .list();
//
//            log.info("Retrieved {} users from Keycloak", users.size());
//            return users;
//
//        } catch (Exception e) {
//            log.error("Error getting all users: {}", e.getMessage());
//            throw new RuntimeException("Failed to get users: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Search users by criteria
//     */
//    public List<UserRepresentation> searchUsers(String searchTerm) {
//        try {
//            List<UserRepresentation> users = keycloak.realm(realm)
//                    .users()
//                    .search(searchTerm);
//
//            log.info("Found {} users matching search term: {}", users.size(), searchTerm);
//            return users;
//
//        } catch (Exception e) {
//            log.error("Error searching users: {}", e.getMessage());
//            throw new RuntimeException("Failed to search users: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Send email verification
//     */
//    public void sendVerificationEmail(String userId) {
//        try {
//            keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .sendVerifyEmail();
//
//            log.info("Verification email sent to user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error sending verification email to user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to send verification email: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Send password reset email
//     */
//    public void sendPasswordResetEmail(String userId) {
//        try {
//            keycloak.realm(realm)
//                    .users()
//                    .get(userId)
//                    .executeActionsEmail(Collections.singletonList("UPDATE_PASSWORD"));
//
//            log.info("Password reset email sent to user: {}", userId);
//
//        } catch (Exception e) {
//            log.error("Error sending password reset email to user {}: {}", userId, e.getMessage());
//            throw new RuntimeException("Failed to send password reset email: " + e.getMessage(), e);
//        }
//    }
//}


// TODO Implement KeycloakUserService

package com.example.userservice.business.impl;

import com.example.userservice.persistence.entity.Role;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakUserService {

    private final Keycloak keycloak;

    @Value("${keycloak.realm}")
    private String realm;

    public String createKeycloakUser(String username, String email, String password,
                                     String firstName, String lastName, Role roleEnum) {
        try {
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            user.setEmail(email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEnabled(true);
            user.setEmailVerified(true);

            Response response = usersResource.create(user);
            int status = response.getStatus();
            if (status != 201) {
                String err = "Failed to create user in Keycloak. Status=" + status;
                response.close();
                throw new RuntimeException(err);
            }
            URI location = response.getLocation();
            response.close();
            String locationPath = location.getPath();
            String userId = locationPath.substring(locationPath.lastIndexOf('/') + 1);

            setUserPassword(userId, password);

            // assign role
            try {
                assignRealmRoleIfExists(userId, roleEnum.name());
            } catch (Exception ex) {
                // fallback: strip ROLE_ prefix
                assignRealmRoleIfExists(userId, roleEnum.name().replaceFirst("^ROLE_", ""));
            }

            log.info("Created Keycloak user {} with role {}", username, roleEnum.name());
            return userId;
        } catch (Exception e) {
            log.error("Error creating user in Keycloak: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void setUserPassword(String userId, String password) {
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(password);
        cred.setTemporary(false);
        keycloak.realm(realm).users().get(userId).resetPassword(cred);
    }

    private void assignRealmRoleIfExists(String userId, String roleName) {
        RealmResource realmResource = keycloak.realm(realm);
        RoleRepresentation roleRep = realmResource.roles().get(roleName).toRepresentation();
        realmResource.users().get(userId).roles().realmLevel().add(Collections.singletonList(roleRep));
    }

    public void deleteKeycloakUser(String userId) {
        keycloak.realm(realm).users().get(userId).remove();
    }

    public UserRepresentation getUserByUsername(String username) {
        List<UserRepresentation> users = keycloak.realm(realm).users().search(username, true);
        return users.isEmpty() ? null : users.get(0);
    }

    public void updateKeycloakUser(String keycloakId, String email, String firstName, String lastName) {
        UserRepresentation user = keycloak.realm(realm).users().get(keycloakId).toRepresentation();
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        keycloak.realm(realm).users().get(keycloakId).update(user);
    }
}
