package com.sistema.inventario.config;

import com.sistema.inventario.security.JwtAuthenticationFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Seguridad por JWT (stateless).
 *
 * <p>Ya no hay HttpSession ni JSESSIONID: el estado de "quien es el usuario"
 * viaja en el token que el cliente manda en cada peticion. Por eso
 * SessionCreationPolicy.STATELESS, que le dice a Spring que ni cree sesion ni
 * la use.
 *
 * <p>El logout tampoco invalida nada en el servidor (no hay servidor que sepa
 * del token): simplemente el cliente borra el suyo. El endpoint /api/auth/logout
 * se conserva para no romper el contrato del frontend y devuelve 200.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                // El front vive en otro origen (http://localhost:5173): Security debe
                // consultar las reglas CORS en vez de bloquear el preflight OPTIONS.
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable()) // academico: front separado / Postman
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // El filtro JWT va justo antes del de autenticacion por formulario
                // (este ultimo esta deshabilitado): es el orden estandar.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // El preflight nunca exige autenticacion: solo anuncia el permiso.
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // Cuando un controller lanza una excepcion, el contenedor
                        // reenvia la peticion a /error. Ese segundo paso llega sin
                        // contexto (el filtro JWT no corre en un dispatch de error),
                        // asi que sin esta linea cualquier error del backend
                        // terminaria en 401 y el frontend creeria que la sesion
                        // expiro. Se deja pasar el dispatch de error para que llegue
                        // el 400/500 real con su mensaje.
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.ASYNC).permitAll()
                        .requestMatchers("/api/auth/login",
                                "/api/auth/logout",
                                "/v3/api-docs/**",
                                "/v3/api-docs",
                                "/swagger-ui/**",
                                "/swagger-ui.html").permitAll()
                        // Puerta exterior por modulo: los 3 roles entran al catalogo.
                        // El permiso fino de cada accion vive en @PreAuthorize
                        // (ProductoController / CategoriaController / IngresoController).
                        .requestMatchers("/api/ingresos/**").hasAuthority("ingreso.registrar")
                        .requestMatchers("/api/inventario/**")
                            .hasAnyRole("ADMIN", "JEFE_ALMACEN", "AUXILIAR_ALMACEN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                // 401 = no hay token o el token no sirve. Sin esto Spring responde
                // 403 tambien en ese caso (Http403ForbiddenEntryPoint por defecto)
                // y el frontend no podria distinguir "expiro mi sesion" de
                // "no tengo permiso", que es 403 de verdad.
                .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(401);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"message\":\"No autenticado o token invalido\"}");
                }))
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        // No hay sesion que invalidar ni cookie que borrar: el token
                        // lo descarta el navegador. El endpoint se conserva para no
                        // romper el contrato del frontend y responde 200.
                        .logoutSuccessHandler((req, res, auth) -> res.setStatus(200))
                );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}