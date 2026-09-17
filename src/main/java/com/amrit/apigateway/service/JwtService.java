package com.amrit.apigateway.service;

import com.amrit.apigateway.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;


    private SecretKey getSigningKey() {

        return Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8)
        );
    }


    public String generateAccessToken(User user) {

        Map<String, Object> claims = new HashMap<>();

        claims.put("userId", user.getId());
        claims.put("role", user.getRole().name());
        claims.put("tokenType", "ACCESS");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(
                        new Date(
                                System.currentTimeMillis()
                                        + accessTokenExpiration
                        )
                )
                .signWith(getSigningKey())
                .compact();
    }


    public String generateRefreshToken(User user) {

        Map<String, Object> claims = new HashMap<>();

        claims.put("userId", user.getId());
        claims.put("tokenType", "REFRESH");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(
                        new Date(
                                System.currentTimeMillis()
                                        + refreshTokenExpiration
                        )
                )
                .signWith(getSigningKey())
                .compact();
    }


    public String extractUsername(String token) {

        return extractAllClaims(token).getSubject();
    }


    public String extractTokenType(String token) {

        return extractAllClaims(token)
                .get("tokenType", String.class);
    }


    public String extractUserId(String token) {

        return extractAllClaims(token)
                .get("userId", String.class);
    }


    public Date extractExpiration(String token) {

        return extractAllClaims(token)
                .getExpiration();
    }


    private Claims extractAllClaims(String token) {

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public boolean isTokenExpired(String token) {

        return extractExpiration(token)
                .before(new Date());
    }


    public boolean isTokenValid(
            String token,
            UserDetails userDetails
    ) {

        try {

            String username =
                    extractUsername(token);

            return username.equals(
                    userDetails.getUsername()
            )
                    && !isTokenExpired(token);

        } catch (Exception e) {

            return false;
        }
    }

}