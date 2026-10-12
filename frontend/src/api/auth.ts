import { api } from './client';
import { limpiarToken } from './tokenStore';
import type { LoginResponse } from './types';

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>('/api/auth/login', { username, password });
  return data;
}

export async function me(): Promise<LoginResponse> {
  const { data } = await api.get<LoginResponse>('/api/auth/me');
  return data;
}

/** Logout SOLO en el navegador: el JWT es stateless, no hay servidor que lo
 *  pueda revocar, asi que la sesion se cierra borrando el token guardado.
 *  (El backend sigue exponiendo POST /api/auth/logout, pero no invalida nada.) */
export async function logout(): Promise<void> {
  limpiarToken();
}