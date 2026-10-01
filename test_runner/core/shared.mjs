import { ApiClient } from './client.mjs';
import { AuthContext } from '../fixtures/auth_context.mjs';
import { ResourceSeeder } from '../fixtures/resource_seed.mjs';

export const BASE_URL = process.env.TARGET_URL || 'http://localhost:4000';
export const apiClient = new ApiClient(BASE_URL);
export const auth = new AuthContext(apiClient);
export const seeder = new ResourceSeeder(apiClient);
