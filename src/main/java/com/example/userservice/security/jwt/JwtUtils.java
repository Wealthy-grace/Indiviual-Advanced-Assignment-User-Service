//package com.example.userservice.security.jwt;
//
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.UnsupportedJwtException;
//import io.jsonwebtoken.io.Decoders;
//import io.jsonwebtoken.security.Keys;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.Pattern;
//import jakarta.validation.constraints.Size;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Component;
//
//import java.security.Key;
//import java.util.Date;
//
//@Component
//public class JwtUtils {
//    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
//
//    @Value("${spring.app.jwtSecret}")
//    private String jwtSecret;
//
//    @Value("${spring.app.jwtExpirationMs}")
//    private int jwtExpirationMs;
//
//    /**
//     * Extracts the JWT from the Authorization header.
//     */
//    public String getJwtFromHeader(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        logger.debug("Authorization Header: {}", bearerToken);
//        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
//    }
//
//    /**
//     * Generates a JWT for the given username.
//     */
//    public String generateTokenFromUsername(
//            @NotBlank(message = "Username is required")
//            @Size(min = 4, max = 30, message = "Username must be between 4 and 30 characters")
//            @Pattern(
//                    regexp = "^[a-zA-Z0-9._-]{4,30}$",
//                    message = "Username can contain letters, numbers, dots, underscores, and hyphens"
//            )
//            String username
//    ) {
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
//                .signWith(getSigningKey())
//                .compact();
//    }
//
//    /**
//     * Extracts the username from a JWT token.
//     */
//    public String getUserNameFromJwtToken(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(getSigningKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody()
//                .getSubject();
//    }
//
//    /**
//     * Returns the HMAC signing key based on the JWT secret, base64-decoded.
//     */
//    private Key getSigningKey() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
//    }
//
//    /**
//     * Validates a JWT token, logging specific reasons on failure.
//     */
//    public boolean validateJwtToken(String authToken) {
//        try {
//            Jwts.parserBuilder()
//                    .setSigningKey(getSigningKey())
//                    .build()
//                    .parseClaimsJws(authToken);
//            return true;
//        } catch (MalformedJwtException e) {
//            logger.error("Invalid JWT token: {}", e.getMessage());
//        } catch (ExpiredJwtException e) {
//            logger.error("JWT token is expired: {}", e.getMessage());
//        } catch (UnsupportedJwtException e) {
//            logger.error("JWT token is unsupported: {}", e.getMessage());
//        } catch (IllegalArgumentException e) {
//            logger.error("JWT claims string is empty: {}", e.getMessage());
//        }
//        return false;
//    }
//}


// new Updated Code

package com.example.userservice.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * Extracts the JWT token from the Authorization header.
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Generates a JWT token from the provided username.
     */
    public String generateTokenFromUsername(
            @NotBlank(message = "Username is required")
            @Size(min = 4, max = 30, message = "Username must be between 4 and 30 characters")
            @Pattern(
                    regexp = "^[a-zA-Z0-9._-]{4,30}$",
                    message = "Username can contain letters, numbers, dots, underscores, and hyphens"
            )
            String username
    ) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extracts the username (subject) from a JWT token.
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Returns HMAC signing key derived from the base64 encoded secret string.
     */
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Validates the JWT token and logs specific issues on failure.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
