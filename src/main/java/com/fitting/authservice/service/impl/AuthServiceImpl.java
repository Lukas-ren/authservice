package com.fitting.authservice.service.impl;

import com.fitting.authservice.client.UserClient;
import com.fitting.authservice.dto.LoginRequest;
import com.fitting.authservice.dto.RegisterRequest;
import com.fitting.authservice.dto.AuthResponse;
import com.fitting.authservice.dto.TokenValidationResponse;
import com.fitting.authservice.exception.BusinessException;
import com.fitting.authservice.exception.ResourceNotFoundException;
import com.fitting.authservice.exception.UnauthorizedException;
import com.fitting.authservice.util.ApiResponse;
import com.fitting.authservice.util.JwtUtil;
import com.fitting.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserClient userClient;
    private final JwtUtil jwtUtil;

    // ── Login ───────────────────────────────────────────────────────────────────

    @Override
    public AuthResponse login(LoginRequest request) {
        log.info("Intento de login para: {}", request.getEmail());

        // 1. Obtener usuario desde user-service
        Map<String, Object> userData = fetchUserByEmail(request.getEmail());

        // 2. Validar contraseña (hash simple, igual que user-service)
        String storedPassword = (String) userData.get("password");
        String hashedInput    = Integer.toHexString(request.getPassword().hashCode());

        if (!hashedInput.equals(storedPassword)) {
            log.warn("Contraseña incorrecta para: {}", request.getEmail());
            throw new UnauthorizedException("Credenciales inválidas");
        }

        // 3. Generar token
        Long   userId = Long.valueOf(userData.get("id").toString());
        String email  = (String) userData.get("email");
        String name   = (String) userData.get("name");
        String role   = (String) userData.get("role");

        String token = jwtUtil.generateToken(userId, email, role);
        log.info("Login exitoso para: {}", email);

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(userId)
                .name(name)
                .email(email)
                .role(role)
                .expiresIn(jwtUtil.getExpirationMs())
                .build();
    }

    // ── Registro ────────────────────────────────────────────────────────────────

    @Override
    public AuthResponse register(RegisterRequest request) {
        log.info("Registro de nuevo usuario: {}", request.getEmail());

        // 1. Crear usuario en user-service vía Feign
        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("name",     request.getName());
        userPayload.put("email",    request.getEmail());
        userPayload.put("password", request.getPassword());
        userPayload.put("role",     request.getRole().name());

        Map<String, Object> createdUser = createUser(userPayload);

        // 2. Generar token inmediatamente tras el registro
        Long   userId = Long.valueOf(createdUser.get("id").toString());
        String email  = (String) createdUser.get("email");
        String name   = (String) createdUser.get("name");
        String role   = (String) createdUser.get("role");

        String token = jwtUtil.generateToken(userId, email, role);
        log.info("Registro exitoso para: {}", email);

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(userId)
                .name(name)
                .email(email)
                .role(role)
                .expiresIn(jwtUtil.getExpirationMs())
                .build();
    }

    // ── Validar token ───────────────────────────────────────────────────────────

    @Override
    public TokenValidationResponse validateToken(String token) {
        log.debug("Validando token");

        if (!jwtUtil.isTokenValid(token)) {
            return TokenValidationResponse.builder()
                    .valid(false)
                    .build();
        }

        return TokenValidationResponse.builder()
                .valid(true)
                .userId(jwtUtil.extractUserId(token))
                .email(jwtUtil.extractEmail(token))
                .role(jwtUtil.extractRole(token))
                .build();
    }

    // ── Helpers Feign ───────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchUserByEmail(String email) {
        try {
            ApiResponse<Map<String, Object>> response = userClient.findByEmail(email);
            if (response == null || !response.isSuccess() || response.getData() == null) {
                throw new ResourceNotFoundException("Usuario con email " + email + " no encontrado");
            }
            return response.getData();
        } catch (ResourceNotFoundException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Error consultando user-service para {}: {}", email, ex.getMessage());
            throw new UnauthorizedException("Credenciales inválidas");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> createUser(Map<String, Object> payload) {
        try {
            ApiResponse<Map<String, Object>> response = userClient.createUser(payload);
            if (response == null || !response.isSuccess() || response.getData() == null) {
                throw new BusinessException("No se pudo crear el usuario");
            }
            return response.getData();
        } catch (BusinessException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Error creando usuario en user-service: {}", ex.getMessage());
            throw new BusinessException("Error al registrar el usuario: " + ex.getMessage());
        }
    }
}