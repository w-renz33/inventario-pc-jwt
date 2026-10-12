package com.sistema.inventario.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro que corre antes de la autorizacion de cada peticion: si encuentra un
 * token valido, deja al usuario autenticado en el SecurityContext.
 *
 * <p>Con sesiones esto lo hacia el contenedor con el JSESSIONID. Con JWT lo
 * hace este filtro, leyendo la cabecera {@code Authorization: Bearer <token>}.
 * Si no hay cabecera (login, swagger, preflight) la peticion sigue su curso
 * como anonima y seran las reglas de SecurityConfig las que decidan.
 *
 * <p>Un token invalido NO bloquea la peticion aqui: se descarta y queda como
 * anonima, asi el 401 lo produce un solo punto de entrada (el
 * AuthenticationEntryPoint de SecurityConfig) en vez de duplicar aqui la
 * respuesta de error.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIJO_BEARER = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String token = tokenDe(request);
        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            autenticar(token, request);
        }
        filterChain.doFilter(request, response);
    }

    /** Header "Authorization: Bearer x" -> "x"; null si no viene o no es Bearer. */
    private static String tokenDe(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(PREFIJO_BEARER)) {
            return null;
        }
        String token = header.substring(PREFIJO_BEARER.length()).trim();
        return token.isEmpty() ? null : token;
    }

    /**
     * Reconstruye la autenticacion desde los claims del token. Silencioso: si
     * el token esta vencido, manipulado o malformado se descarta y la peticion
     * sigue como anonima.
     */
    private void autenticar(String token, HttpServletRequest request) {
        Claims claims = jwtService.claimsSiValidos(token);
        if (claims == null) {
            return;
        }
        String username = claims.getSubject();
        if (username == null || username.isBlank()) {
            return;
        }
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username,
                null,
                jwtService.authoritiesDe(claims)
        );
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}