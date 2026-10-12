package com.sistema.inventario.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Documentacion de la API en /swagger-ui.html.
 *
 * <p>La autenticacion es por JWT, asi que se declara un SecurityScheme de tipo
 * HTTP Bearer: eso enciende el boton "Authorize" de Swagger UI, donde se pega el
 * token (sin la palabra "Bearer") y todas las peticiones lo anaden en la
 * cabecera Authorization. El unico endpoint sin token es POST /api/auth/login.
 */
@Configuration
public class OpenApiConfig {

    /** Nombre del esquema, el mismo con el que se pide el token en /authorize. */
    private static final String ESQUEMA = "bearerAuth";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Sistema de Inventario API")
                        .version("1.0")
                        .description("""
                                API de inventario de componentes PC con autenticacion por JWT.

                                Como probarla: 1) POST /api/auth/login con usuario y contrasena; la
                                respuesta incluye el campo "token". 2) Pegar ese token (solo el texto,
                                sin la palabra Bearer) en el boton "Authorize" de Swagger UI.
                                3) El resto de endpoints ya viaja con la cabecera Authorization.

                                El frontend hace lo mismo: guarda el token y lo reenvia en cada
                                peticion. GET /api/auth/me confirma que el token sigue vigente.

                                Autorizacion por rol: ADMIN, JEFE_ALMACEN y AUXILIAR_ALMACEN. Cada rol tiene
                                un subconjunto de permisos recurso.accion; el detalle esta en
                                /api/auth/me (campo permisos).""")
                        .contact(new Contact()
                                .name("Soporte")
                                .email("soporte@inventario.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("http://springdoc.org")))
                .components(new Components().addSecuritySchemes(ESQUEMA, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Token devuelto por POST /api/auth/login")))
                .addSecurityItem(new SecurityRequirement().addList(ESQUEMA));
    }
}