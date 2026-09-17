package com.amrit.apigateway.dto;

public record AuthResponse(

        String accessToken,

        String refreshToken,

        String tokenType,

        String userId,

        String name,

        String email,

        String role

) {
}