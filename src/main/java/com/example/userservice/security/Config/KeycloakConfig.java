
package com.example.userservice.security.Config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Keycloak Admin Client Configuration
 *
 * This configuration creates a Keycloak admin client that uses SERVICE ACCOUNT authentication
 * to perform administrative operations like creating, updating, and deleting users.
 *
 * IMPORTANT: For this to work, you MUST configure the following in Keycloak Admin Console:
 *
 * 1. Enable Service Account for 'user-service' client:
 *    - Go to: Clients → user-service → Settings tab
 *    - Enable "Client authentication" = ON
 *    - Enable "Service accounts roles" = ON
 *    - Click Save
 *
 * 2. Assign required roles to the service account:
 *    - Go to: Clients → user-service → Service accounts roles tab
 *    - In "Client Roles" dropdown, select "realm-management"
 *    - Assign these roles:
 *      • manage-users (Required - allows creating/updating/deleting users)
 *      • view-users (Optional - allows viewing user details)
 *      • query-users (Optional - allows searching users)
 *
 * 3. Verify client credentials:
 *    - Go to: Clients → user-service → Credentials tab
 *    - Copy the Client Secret and update application.properties
 *
 * Without these configurations, you will get "403 Forbidden" errors when trying to
 * create or manage users programmatically.
 */
@Configuration
public class KeycloakConfig {

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    /**
     * Creates a Keycloak Admin Client using Service Account (client_credentials) authentication.
     *
     * This client will be used by KeycloakUserService to perform administrative operations.
     *
     * Grant Type: client_credentials
     * - This is the correct grant type for service-to-service authentication
     * - The service account represents your application (not a human user)
     * - Permissions are managed through the service account's roles
     *
     * @return Keycloak admin client instance
     */
    @Bean
    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)           // http://localhost:8080
                .realm(realm)                   // friendly-housing
                .grantType("client_credentials") // Service account authentication
                .clientId(clientId)             // user-service
                .clientSecret(clientSecret)     // Your client secret from Keycloak
                .build();
    }
}


