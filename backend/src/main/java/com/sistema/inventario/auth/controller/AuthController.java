package com.sistema.inventario.auth.controller;

import com.sistema.inventario.auth.dto.LoginRequest;
import com.sistema.inventario.auth.dto.LoginResponse;
import com.sistema.inventario.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /** No hay registro: las cuentas las crea el DataSeeder. Solo login. */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Quien soy segun el token que mando en Authorization: Bearer.
     * El Authentication lo arma JwtAuthenticationFilter, no la sesion.
     */
    @GetMapping("/me")
    public ResponseEntity<LoginResponse> me(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(authService.me(authentication.getName()));
    }
}