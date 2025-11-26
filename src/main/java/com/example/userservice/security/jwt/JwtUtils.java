//package com.example.userservice.security.jwt;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.UnsupportedJwtException;
//import io.jsonwebtoken.io.Decoders;
//import io.jsonwebtoken.security.Keys;
//import jakarta.servlet.http.HttpServletRequest;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import java.security.Key;
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
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
//     * Extracts the JWT token from the Authorization header.
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
//     * Generates a JWT token from username only (backward compatibility)
//     * WARNING: This method doesn't include role - use generateTokenFromUserDetails instead
//     */
//    @Deprecated
//    public String generateTokenFromUsername(String username) {
//        logger.warn("generateTokenFromUsername called - this method doesn't include role claim");
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);
//
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(now)
//                .setExpiration(expiryDate)
//                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
//                .compact();
//    }
//
//    /**
//     * Generates a JWT token with username and role from UserDetails
//     * THIS IS THE METHOD YOU SHOULD USE FOR LOGIN
//     */
//    public String generateTokenFromUserDetails(UserDetails userDetails) {
//        Map<String, Object> claims = new HashMap<>();
//
//        // Extract role from authorities and add to claims
//        String role = userDetails.getAuthorities().stream()
//                .findFirst()
//                .map(GrantedAuthority::getAuthority)
//                .map(authority -> authority.replace("ROLE_", "")) // Remove ROLE_ prefix
//                .orElse("STUDENT"); // Default to STUDENT if no role found
//
//        claims.put("role", role);
//
//        logger.info("Generating JWT token for user: {}, role: {}", userDetails.getUsername(), role);
//
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setSubject(userDetails.getUsername())
//                .setIssuedAt(now)
//                .setExpiration(expiryDate)
//                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
//                .compact();
//    }
//
//    /**
//     * Extracts the username (subject) from a JWT token.
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
//     * Extracts the role from a JWT token.
//     */
//    public String getRoleFromJwtToken(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(getSigningKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        return claims.get("role", String.class);
//    }
//
//    /**
//     * Returns HMAC signing key derived from the base64 encoded secret string.
//     */
//    private Key getSigningKey() {
//        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
//    }
//
//    /**
//     * Validates the JWT token and logs specific issues on failure.
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