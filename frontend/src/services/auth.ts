import { http } from './http'

export interface AuthUser {
  id: string
  email: string
  full_name: string
  role: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface AuthTokenResponse {
  access_token: string
  token_type: string
}

export interface RegisterRequest {
  email: string
  full_name: string
  password: string
}

export const authService = {
  login: (email: string, password: string) =>
    http.post<AuthTokenResponse>('/auth/login', { email, password }),
  register: (request: RegisterRequest) => http.post<AuthUser>('/auth/register', request),
  me: () => http.get<AuthUser>('/auth/me'),
}