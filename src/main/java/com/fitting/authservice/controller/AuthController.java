package com.fitting.authservice.controller;

import com.fitting.authservice.dto.LoginRequest;
import com.fitting.authservice.dto.RegisterRequest;
import com.fitting.authservice.dto.AuthResponse;
import com.fitting.authservice.dto.TokenValidationResponse;
import com.fitting.authservice.service.AuthService;
import com.fitting.authservice.util.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        log.info("POST /api/v1/auth/login — email: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.ok("Login exitoso",
                authService.login(request)));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        log.info("POST /api/v1/auth/register — email: {}", request.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Registro exitoso",
                        authService.register(request)));
    }

    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validate(
            @RequestHeader("Authorization") String authHeader) {
        log.info("POST /api/v1/auth/validate");
        String token = extractToken(authHeader);
        return ResponseEntity.ok(ApiResponse.ok("Token validado",
                authService.validateToken(token)));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> me(
            @RequestHeader("Authorization") String authHeader) {
        log.info("GET /api/v1/auth/me");
        String token = extractToken(authHeader);
        TokenValidationResponse response = authService.validateToken(token);
        if (!response.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Token inválido o expirado"));
        }
        return ResponseEntity.ok(ApiResponse.ok("Usuario autenticado", response));
    }

    // ── Helper ──────────────────────────────────────────────────────────────────

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new com.fitting.authservice.exception.UnauthorizedException(
                "Header Authorization inválido. Formato esperado: Bearer <token>");
    }
}