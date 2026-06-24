package com.fitting.authservice.client;

import com.fitting.authservice.util.ApiResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@FeignClient(name = "user-service", url = "${user.service.url}")
public interface UserClient {

    // Obtiene usuario por email para validar credenciales
    @GetMapping("/api/v1/users/email/{email}")
    ApiResponse<Map<String, Object>> findByEmail(@PathVariable String email);

    // Crea el usuario en user-service durante el registro
    @PostMapping("/api/v1/users")
    ApiResponse<Map<String, Object>> createUser(@RequestBody Map<String, Object> request);
}