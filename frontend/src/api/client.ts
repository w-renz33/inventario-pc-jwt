import axios from 'axios';
import { leerToken, limpiarToken } from './tokenStore';

/** Cliente unico. Auth por JWT: sin cookies ni withCredentials.
 *  El interceptor de peticion mete "Authorization: Bearer <token>" en cada
 *  llamada si hay token guardado. */
export const api = axios.create({
  baseURL: 'http://localhost:8080',
  headers: { 'Content-Type': 'application/json' },
});

/** Anade el token a la peticion. El backend lo lee en JwtAuthenticationFilter. */
api.interceptors.request.use((config) => {
  const token = leerToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/** Token vencido, invalido o manipulado -> borrar y volver al login.
 *  El back responde 401 cuando el JWT no pasa la validacion; el 403 tambien
 *  significa "sin permiso", asi que solo redirige en /me o 401. */
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const url = err.config?.url ?? '';
    const sinSesion =
      err.response?.status === 401 || (err.response?.status === 403 && url.includes('/api/auth/me'));
    if (sinSesion && window.location.pathname !== '/login') {
      limpiarToken();
      window.location.href = '/login?expirada=1';
    }
    return Promise.reject(err);
  },
);

/** Mensaje legible para errores de negocio (hoy llegan como 500). */
export function mensajeError(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const data = err.response?.data as { message?: string; mensaje?: string } | string | undefined;
    if (typeof data === 'string' && data.length > 0) return data;
    if (data && typeof data === 'object') return data.message ?? data.mensaje ?? fallback;
    if (err.response?.status === 403) return 'Sin permiso para esta accion.';
    if (err.response?.status === 400) return 'Datos invalidos. Revisa el formulario.';
  }
  return fallback;
}