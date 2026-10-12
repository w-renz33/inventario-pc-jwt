/** Llave unica del token en localStorage. Vive aparte para que client.ts y
 *  auth.ts no se importen en circulo (el interceptor necesita leerla y login
 *  necesita guardarla). */
const CLAVE = 'inventario_token';

/** Token guardado, o null si no hay sesion. */
export function leerToken(): string | null {
  return localStorage.getItem(CLAVE);
}

/** Guarda el token que devolvio POST /api/auth/login. */
export function guardarToken(token: string): void {
  localStorage.setItem(CLAVE, token);
}

/** Cierra la sesion en el navegador: sin token no hay Authorization que mandar. */
export function limpiarToken(): void {
  localStorage.removeItem(CLAVE);
}