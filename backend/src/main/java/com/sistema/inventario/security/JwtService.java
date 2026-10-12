package com.sistema.inventario.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Emisor y verificador de JWT (firma HMAC-SHA256, algoritmo HS256).
 *
 * <p>Un JWT son tres partes separadas por puntos:
 * <pre>BASE64URL(header).BASE64URL(payload).BASE64URL(firma)</pre>
 * El header y el payload solo van codificados en base64 (NO cifrados: se leen
 * sin la clave), y la firma es lo que impide que alguien los modifique. Al
 * abrir el token en jwt.io se ve el contenido; lo que no se puede es alterarlo
 * sin que la firma deje de coincidir.
 *
 * <p>Payload de este proyecto:
 * <ul>
 *   <li>{@code sub}: username del usuario (obligatorio en el estándar).</li>
 *   <li>{@code roles}: nombres de rol, sin el prefijo ROLE_.</li>
 *   <li>{@code permisos}: codigos de permiso (recurso.accion).</li>
 *   <li>{@code iat}: fecha de emision. {@code exp}: fecha de expiracion.</li>
 * </ul>
 *
 * <p>Los claims de roles y permisos hacen que el token sea autosuficiente: el
 * filtro reconstruye las authorities sin volver a consultar la base de datos.
 * El precio es que un cambio de permisos no surte efecto hasta que el token
 * expira o se vuelve a entrar.
 */
@Service
public class JwtService {

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISOS = "permisos";

    private final SecretKey key;
    private final long expirationMs;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.expiration-ms}") long expirationMs) {
        // HS256 exige una llave de al menos 256 bits (32 bytes): si el secreto es
        // mas corto, Keys.hmacShaKeyFor lanza WeakKeyException al arrancar.
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    /**
     * Firma un token para el usuario con su foto de permisos actual.
     *
     * @param username sujeto del token (sub)
     * @param roles    nombres de rol, p. ej. ADMIN
     * @param permisos codigos, p. ej. ingreso.registrar
     */
    public String generarToken(String username, List<String> roles, List<String> permisos) {
        Date ahora = new Date();
        Date expira = new Date(ahora.getTime() + expirationMs);
        return Jwts.builder()
                .subject(username)
                .claim(CLAIM_ROLES, roles)
                .claim(CLAIM_PERMISOS, permisos)
                .issuedAt(ahora)
                .expiration(expira)
                .signWith(key)
                .compact();
    }

    /**
     * Claims del token si la firma y la expiracion son correctas; null si no.
     *
     * <p>La validacion es la parte que mas se usa: {@code parseSignedClaims}
     * comprueba que la firma se haya hecho con ESTA clave (si alguien altera
     * una letra del payload, el HMAC ya no cuadra y lanza SignatureException) y
     * que no haya vencido (ExpiredJwtException). Cualquier excepcion de JWT se
     * traduce a null para no filtrarle al atacante que parte fallo.
     */
    public Claims claimsSiValidos(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Authorities para el SecurityContext, derivadas de los claims con las
     * mismas reglas que CustomUserDetailsService: rol -> ROLE_X, permiso tal
     * cual. Si divergen de ahi, los @PreAuthorize dejan de funcionar.
     */
    public Collection<SimpleGrantedAuthority> authoritiesDe(Claims claims) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.addAll(authoritiesDe(claims, CLAIM_ROLES, true));
        authorities.addAll(authoritiesDe(claims, CLAIM_PERMISOS, false));
        return authorities;
    }

    /**
     * Lee un claim que es una lista de strings. Si viene ausente o con otro
     * tipo, devuelve lista vacia en vez de romper la peticion.
     */
    private static List<SimpleGrantedAuthority> authoritiesDe(Claims claims, String claim, boolean prefijoRole) {
        Object valor = claims.get(claim);
        if (!(valor instanceof Collection<?> coleccion)) {
            return List.of();
        }
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Object item : coleccion) {
            String texto = item.toString();
            if (texto.isBlank()) {
                continue;
            }
            authorities.add(new SimpleGrantedAuthority(prefijoRole ? "ROLE_" + texto : texto));
        }
        return authorities;
    }
}