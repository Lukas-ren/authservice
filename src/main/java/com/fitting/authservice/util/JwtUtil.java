package com.fitting.authservice.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration-ms}")
    private long expirationMs;

    // ── Generar token ───────────────────────────────────────────────────────────

    public String generateToken(Long userId, String email, String role) {
        return Jwts.builder()
                .subject(email)
                .claim("userId", userId)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    // ── Validar token ───────────────────────────────────────────────────────────

    public boolean isTokenValid(String token) {
        try {
            getClaims(token);
            return true;
        } catch (ExpiredJwtException ex) {
            log.warn("Token expirado: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.warn("Token no soportado: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.warn("Token malformado: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.warn("Token vacío o nulo: {}", ex.getMessage());
        }
        return false;
    }

    // ── Extraer claims ──────────────────────────────────────────────────────────

    public String extractEmail(String token) {
        return getClaims(token).getSubject();
    }

    public Long extractUserId(String token) {
        return getClaims(token).get("userId", Long.class);
    }

    public String extractRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    // ── Helpers privados ────────────────────────────────────────────────────────

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
}