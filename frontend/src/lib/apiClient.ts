/**
 * API Client with Auth Token (Week 4: RBAC)
 *
 * Automatically adds JWT token to all API requests
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface RequestOptions extends RequestInit {
  params?: Record<string, string | number | boolean>;
}

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private getAuthToken(): string | null {
    return localStorage.getItem('venti_auth_token');
  }

  private buildUrl(path: string, params?: Record<string, string | number | boolean>): string {
    const url = new URL(path, this.baseUrl);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.append(key, String(value));
      });
    }

    return url.toString();
  }

  private async request<T>(
    path: string,
    options: RequestOptions = {}
  ): Promise<T> {
    const { params, ...fetchOptions } = options;
    const url = this.buildUrl(path, params);

    const token = this.getAuthToken();
    const headers = new Headers(fetchOptions.headers);

    // Add auth token if available
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    // Add Content-Type for JSON requests
    if (!headers.has('Content-Type') && fetchOptions.body) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(url, {
      ...fetchOptions,
      headers,
    });

    // Handle 401 Unauthorized - redirect to login
    if (response.status === 401) {
      localStorage.removeItem('venti_auth_token');
      localStorage.removeItem('venti_user');
      window.location.href = '/auth';
      throw new Error('Unauthorized');
    }

    // Handle errors
    if (!response.ok) {
      const error = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail || 'Request failed');
    }

    // Parse JSON response
    return response.json() as Promise<T>;
  }

  async get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: 'GET' });
  }

  async post<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, {
      ...options,
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async put<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, {
      ...options,
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async patch<T>(path: string, body?: any, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, {
      ...options,
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: 'DELETE' });
  }

  /**
   * Upload file with multipart/form-data
   */
  async upload<T>(path: string, formData: FormData, options?: RequestOptions): Promise<T> {
    const url = this.buildUrl(path, options?.params);
    const token = this.getAuthToken();

    const headers = new Headers(options?.headers);
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    // Don't set Content-Type for FormData - browser will set it with boundary

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (response.status === 401) {
      localStorage.removeItem('venti_auth_token');
      localStorage.removeItem('venti_user');
      window.location.href = '/auth';
      throw new Error('Unauthorized');
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        detail: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.detail || 'Upload failed');
    }

    return response.json() as Promise<T>;
  }
}

export const apiClient = new ApiClient(API_BASE);
