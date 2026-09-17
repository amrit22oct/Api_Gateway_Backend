package com.amrit.apigateway.controller;

import com.amrit.apigateway.dto.AuthResponse;
import com.amrit.apigateway.dto.LoginRequest;
import com.amrit.apigateway.dto.RefreshTokenRequest;
import com.amrit.apigateway.dto.RegisterRequest;
import com.amrit.apigateway.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(

            @Valid
            @RequestBody
            RegisterRequest request

    ) {

        return ResponseEntity.ok(
                authService.register(request)
        );
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(

            @Valid
            @RequestBody
            LoginRequest request

    ) {

        return ResponseEntity.ok(
                authService.login(request)
        );
    }


    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(

            @Valid
            @RequestBody
            RefreshTokenRequest request

    ) {

        return ResponseEntity.ok(
                authService.refresh(request)
        );
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(

            @Valid
            @RequestBody
            RefreshTokenRequest request

    ) {

        authService.logout(
                request.refreshToken()
        );


        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "Logged out successfully"
                )
        );
    }

}