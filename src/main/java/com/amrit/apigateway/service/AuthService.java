package com.amrit.apigateway.service;

import com.amrit.apigateway.dto.AuthResponse;
import com.amrit.apigateway.dto.LoginRequest;
import com.amrit.apigateway.dto.RefreshTokenRequest;
import com.amrit.apigateway.dto.RegisterRequest;
import com.amrit.apigateway.entity.RefreshToken;
import com.amrit.apigateway.entity.Role;
import com.amrit.apigateway.entity.User;
import com.amrit.apigateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    private final RefreshTokenService refreshTokenService;


    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;


    public AuthResponse register(
            RegisterRequest request
    ) {

        if (
                userRepository.existsByEmail(
                        request.email()
                )
        ) {

            throw new RuntimeException(
                    "Email already registered"
            );
        }


        User user =
                User.builder()

                        .name(request.name())

                        .email(request.email())

                        .password(
                                passwordEncoder.encode(
                                        request.password()
                                )
                        )

                        .role(Role.DEVELOPER)

                        .build();


        userRepository.save(user);


        return createAuthResponse(user);
    }


    public AuthResponse login(
            LoginRequest request
    ) {

        authenticationManager.authenticate(

                new UsernamePasswordAuthenticationToken(

                        request.email(),

                        request.password()

                )
        );


        User user =
                userRepository
                        .findByEmail(
                                request.email()
                        )
                        .orElseThrow(
                                () -> new RuntimeException(
                                        "User not found"
                                )
                        );


        return createAuthResponse(user);
    }


    public AuthResponse refresh(
            RefreshTokenRequest request
    ) {

        RefreshToken oldToken =
                refreshTokenService.validate(
                        request.refreshToken()
                );


        String tokenType =
                jwtService.extractTokenType(
                        request.refreshToken()
                );


        if (!"REFRESH".equals(tokenType)) {

            throw new RuntimeException(
                    "Invalid token type"
            );
        }


        User user =
                oldToken.getUser();


        // Rotate refresh token
        refreshTokenService.revoke(
                oldToken
        );


        return createAuthResponse(user);
    }


    public void logout(
            String refreshToken
    ) {

        RefreshToken storedToken =
                refreshTokenService.validate(
                        refreshToken
                );


        refreshTokenService.revoke(
                storedToken
        );
    }


    private AuthResponse createAuthResponse(
            User user
    ) {

        String accessToken =
                jwtService.generateAccessToken(
                        user
                );


        String refreshToken =
                jwtService.generateRefreshToken(
                        user
                );


        refreshTokenService.create(

                user,

                refreshToken,

                refreshTokenExpiration

        );


        return new AuthResponse(

                accessToken,

                refreshToken,

                "Bearer",

                user.getId(),

                user.getName(),

                user.getEmail(),

                user.getRole().name()

        );
    }

}