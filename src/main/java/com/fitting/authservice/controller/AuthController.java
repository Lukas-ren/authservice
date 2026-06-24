package com.fitting.authservice.controller;

import com.fitting.authservice.dto.LoginRequest;
import com.fitting.authservice.dto.RegisterRequest;
import com.fitting.authservice.dto.AuthResponse;
import com.fitting.authservice.dto.TokenValidationResponse;
import com.fitting.authservice.exception.UnauthorizedException;
import com.fitting.authservice.service.AuthService;
import com.fitting.authservice.util.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Tag(name = "Autenticación", description = "Login, registro y validación de tokens JWT")
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Registrar usuario", description = "Crea un nuevo usuario y retorna un token JWT")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Registro exitoso"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Email ya registrado o datos inválidos")
    })
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        log.info("POST /api/v1/auth/register — email: {}", request.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Registro exitoso",
                        authService.register(request)));
    }

    @Operation(summary = "Login", description = "Autentica al usuario y retorna un token JWT")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Login exitoso"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Credenciales inválidas")
    })
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        log.info("POST /api/v1/auth/login — email: {}", request.getEmail());
        return ResponseEntity.ok(ApiResponse.ok("Login exitoso",
                authService.login(request)));
    }

    @Operation(summary = "Validar token", description = "Verifica si un token JWT es válido o está expirado")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Resultado de la validación"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Header Authorization inválido")
    })
    @PostMapping("/validate")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validate(
            @RequestHeader("Authorization") String authHeader) {
        log.info("POST /api/v1/auth/validate");
        String token = extractToken(authHeader);
        return ResponseEntity.ok(ApiResponse.ok("Token validado",
                authService.validateToken(token)));
    }

    @Operation(summary = "Info del usuario autenticado", description = "Retorna los datos del usuario a partir del token")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Token válido"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Token inválido o expirado")
    })
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

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new UnauthorizedException(
                "Header Authorization inválido. Formato esperado: Bearer <token>");
    }
}