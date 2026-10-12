import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import * as authApi from '../api/auth';
import { guardarToken, leerToken } from '../api/tokenStore';
import type { LoginResponse } from '../api/types';

interface AuthContextValue {
  user: LoginResponse | null;
  cargando: boolean;
  entrar: (username: string, password: string) => Promise<void>;
  salir: () => Promise<void>;
  tienePermiso: (permiso: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

interface AuthProviderProps {
  readonly children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<LoginResponse | null>(null);
  const [cargando, setCargando] = useState(true);

  useEffect(() => {
    // Sin token guardado no hay nada que preguntarle al backend: se evita el
    // 401 inicial en /me (que ademas dispararia la redireccion a /login).
    if (!leerToken()) {
      setCargando(false);
      return;
    }
    authApi
      .me()
      .then((data) => {
        // /me devuelve los roles y permisos mas frescos y renueva el token, asi
        // que un cambio de permisos se aplica recargando la pagina.
        guardarToken(data.token);
        setUser(data);
      })
      .catch(() => setUser(null))
      .finally(() => setCargando(false));
  }, []);

  const entrar = useCallback(async (username: string, password: string) => {
    const data = await authApi.login(username, password);
    guardarToken(data.token);
    setUser(data);
  }, []);

  const salir = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const tienePermiso = useCallback(
    (permiso: string) => user?.permisos.includes(permiso) ?? false,
    [user],
  );

  return (
    <AuthContext.Provider value={{ user, cargando, entrar, salir, tienePermiso }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>');
  return ctx;
}