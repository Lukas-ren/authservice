package com.fitting.authservice.service;

import com.fitting.authservice.dto.LoginRequest;
import com.fitting.authservice.dto.RegisterRequest;
import com.fitting.authservice.dto.AuthResponse;
import com.fitting.authservice.dto.TokenValidationResponse;

public interface AuthService {

    AuthResponse login(LoginRequest request);

    AuthResponse register(RegisterRequest request);

    TokenValidationResponse validateToken(String token);
}