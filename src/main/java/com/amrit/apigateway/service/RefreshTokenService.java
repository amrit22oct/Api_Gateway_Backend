package com.amrit.apigateway.service;

import com.amrit.apigateway.entity.RefreshToken;
import com.amrit.apigateway.entity.User;
import com.amrit.apigateway.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;


    public RefreshToken create(
            User user,
            String token,
            long expiration
    ) {

        RefreshToken refreshToken =
                RefreshToken.builder()

                        .token(token)

                        .user(user)

                        .expiryDate(
                                LocalDateTime.now()
                                        .plusSeconds(
                                                expiration / 1000
                                        )
                        )

                        .revoked(false)

                        .build();


        return refreshTokenRepository.save(
                refreshToken
        );
    }


    public RefreshToken validate(
            String token
    ) {

        RefreshToken refreshToken =
                refreshTokenRepository
                        .findByToken(token)
                        .orElseThrow(
                                () -> new RuntimeException(
                                        "Invalid refresh token"
                                )
                        );


        if (refreshToken.isRevoked()) {

            throw new RuntimeException(
                    "Refresh token has been revoked"
            );
        }


        if (
                refreshToken.getExpiryDate()
                        .isBefore(LocalDateTime.now())
        ) {

            throw new RuntimeException(
                    "Refresh token has expired"
            );
        }


        return refreshToken;
    }


    public void revoke(
            RefreshToken refreshToken
    ) {

        refreshToken.setRevoked(true);

        refreshTokenRepository.save(
                refreshToken
        );
    }

}