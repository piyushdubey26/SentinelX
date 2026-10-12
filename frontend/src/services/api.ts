import axios from 'axios';
import { BackendHealth, AuthResponse, Incident, IncidentMetrics, IncidentStatus } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT access token automatically
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinelx_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-handle 401 Unauthorized
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config.url?.includes('/auth/login')) {
      localStorage.removeItem('sentinelx_token');
      localStorage.removeItem('sentinelx_user');
      window.dispatchEvent(new Event('sentinelx_auth_expired'));
    }
    return Promise.reject(error);
  },
);

export const checkBackendHealth = async (): Promise<BackendHealth> => {
  const response = await apiClient.get<BackendHealth>('/health');
  return response.data;
};

export const loginApi = async (email: string, password: string): Promise<AuthResponse> => {
  const response = await apiClient.post<AuthResponse>('/auth/login', { email, password });
  localStorage.setItem('sentinelx_token', response.data.accessToken);
  localStorage.setItem('sentinelx_user', JSON.stringify(response.data.user));
  return response.data;
};

export const logoutApi = async (): Promise<void> => {
  try {
    await apiClient.post('/auth/logout');
  } finally {
    localStorage.removeItem('sentinelx_token');
    localStorage.removeItem('sentinelx_user');
  }
};

export const getMeApi = async () => {
  const response = await apiClient.get('/auth/me');
  return response.data;
};

export const getIncidentsApi = async (params?: {
  limit?: number;
  offset?: number;
  status?: string;
  severity?: string;
}): Promise<{ data: Incident[]; total: number }> => {
  const response = await apiClient.get<{ data: Incident[]; total: number }>('/incidents', { params });
  return response.data;
};

export const getIncidentMetricsApi = async (): Promise<IncidentMetrics> => {
  const response = await apiClient.get<IncidentMetrics>('/incidents/metrics');
  return response.data;
};

export const getIncidentDetailApi = async (id: string): Promise<Incident> => {
  const response = await apiClient.get<Incident>(`/incidents/${id}`);
  return response.data;
};

export const updateIncidentStatusApi = async (id: string, status: IncidentStatus): Promise<Incident> => {
  const response = await apiClient.patch<Incident>(`/incidents/${id}/status`, { status });
  return response.data;
};
