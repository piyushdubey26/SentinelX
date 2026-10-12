import axios from 'axios';
import { BackendHealth } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 8000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const checkBackendHealth = async (): Promise<BackendHealth> => {
  const response = await apiClient.get<BackendHealth>('/health');
  return response.data;
};
