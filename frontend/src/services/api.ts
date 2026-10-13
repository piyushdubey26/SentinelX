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

export const getCandidatesApi = async (params?: {
  limit?: number;
  offset?: number;
  status?: string;
  minConfidence?: number;
}): Promise<{ data: any[]; total: number }> => {
  const response = await apiClient.get<{ data: any[]; total: number }>('/correlation/candidates', { params });
  return response.data;
};

export const promoteCandidateApi = async (id: string): Promise<any> => {
  const response = await apiClient.post(`/correlation/candidates/${id}/promote`);
  return response.data;
};

export const dismissCandidateApi = async (id: string, reason: string): Promise<any> => {
  const response = await apiClient.post(`/correlation/candidates/${id}/dismiss`, { reason });
  return response.data;
};

// ==========================================
// Milestone 2.3 Graph Investigation API
// ==========================================

export const getIncidentGraphApi = async (
  incidentId: string,
  params?: { maxHops?: number; timeWindowHours?: number; includeEvents?: boolean },
): Promise<any> => {
  const response = await apiClient.get(`/investigations/incident/${incidentId}/graph`, { params });
  return response.data;
};

export const getIncidentPathsApi = async (
  incidentId: string,
  params: { sourceId: string; targetId: string; maxDepth?: number },
): Promise<any> => {
  const response = await apiClient.get(`/investigations/incident/${incidentId}/paths`, { params });
  return response.data;
};

export const getIncidentBlastRadiusApi = async (
  incidentId: string,
  params?: { maxHops?: number; timeWindowHours?: number },
): Promise<any> => {
  const response = await apiClient.get(`/investigations/incident/${incidentId}/blast-radius`, { params });
  return response.data;
};

export const getIncidentCyclesApi = async (incidentId: string): Promise<any> => {
  const response = await apiClient.get(`/investigations/incident/${incidentId}/cycles`);
  return response.data;
};

