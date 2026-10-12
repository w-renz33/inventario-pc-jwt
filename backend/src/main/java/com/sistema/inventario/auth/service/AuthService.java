package com.sistema.inventario.auth.service;

import com.sistema.inventario.auth.dto.LoginRequest;
import com.sistema.inventario.auth.dto.LoginResponse;
import com.sistema.inventario.auth.entity.Usuario;
import com.sistema.inventario.auth.entity.UsuarioRol;
import com.sistema.inventario.auth.repository.AuthDao;
import com.sistema.inventario.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    private final AuthDao authDao;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthService(AuthDao authDao,
                       AuthenticationManager authenticationManager,
                       JwtService jwtService) {
        this.authDao = authDao;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    /**
     * Login por JWT: se validan las credenciales y se devuelve un token firmado.
     * No hay nada que guardar en el servidor: el token es el que "recuerda" la
     * sesion, y por eso no se toca HttpSession ni el SecurityContext.
     */
    public LoginResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        return resumen(request.getUsername());
    }

    public LoginResponse me(String username) {
        return resumen(username);
    }

    /**
     * Foto de permisos del usuario + token. Los roles y permisos se leen de la
     * base y se meten DENTRO del token, para que cada peticion posterior se
     * autorice sin volver a consultar (CustomUserDetailsService no se usa en el
     * camino del token; solo sigue haciendo falta para el login).
     */
    private LoginResponse resumen(String username) {
        Usuario usuario = authDao.findUsuarioByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        List<UsuarioRol> urs = authDao.findRolesConRol(usuario.getId());
        List<String> roles = urs.stream().map(ur -> ur.getRol().getNombre()).distinct().toList();
        List<Long> rolIds = urs.stream().map(ur -> ur.getRol().getId()).distinct().toList();
        List<String> permisos = authDao.findPermisosConPermiso(rolIds).stream()
                .map(rp -> rp.getPermiso().getCodigo())
                .distinct()
                .toList();

        String token = jwtService.generarToken(usuario.getUsername(), roles, permisos);
        return new LoginResponse(usuario.getUsername(), roles, permisos, token);
    }
}