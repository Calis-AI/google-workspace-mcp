import { OAuth2Client } from 'google-auth-library';

export interface Account {
  email: string;
  category: string;
  description: string;
  auth_status?: {
    valid: boolean;
    status?: TokenStatusType;
    token?: any;  // Internal use only - not exposed to AI
    reason?: string;
    authUrl?: string;
    requiredScopes?: string[];
  };
  // 新增：认证方式标识
  auth_method?: 'oauth' | 'jwt' | 'hybrid';
  // 新增：JWT相关元数据
  jwt_metadata?: {
    provider: 'supabase';
    claims?: any;
    expiry?: number;
  };
}

export interface AccountsConfig {
  accounts: Account[];
}

export type TokenStatusType = 
  | 'NO_TOKEN'
  | 'VALID'
  | 'INVALID'
  | 'REFRESHED'
  | 'REFRESH_FAILED'
  | 'EXPIRED'
  | 'ERROR';

export interface TokenRenewalResult {
  success: boolean;
  status: TokenStatusType;
  reason?: string;
  token?: any;
  canRetry?: boolean;  // Indicates if a failed refresh can be retried later
}

export interface TokenStatus {
  valid: boolean;
  status: TokenStatusType;
  token?: any;
  reason?: string;
  authUrl?: string;
  requiredScopes?: string[];
}

export interface AuthenticationError extends AccountError {
  authUrl: string;
  requiredScopes: string[];
}

export interface AccountModuleConfig {
  accountsPath?: string;
  oauth2Client?: OAuth2Client;
  // 新增：Supabase配置
  supabaseConfig?: {
    enabled?: boolean;
    url?: string;
    anonKey?: string;
    jwtSecret?: string;
  };
}

export class AccountError extends Error {
  constructor(
    message: string,
    public code: string,
    public resolution: string
  ) {
    super(message);
    this.name = 'AccountError';
  }
}

// 新增JWT相关错误类型
export class JWTError extends AccountError {
  constructor(message: string, code: string, resolution: string) {
    super(message, code, resolution);
    this.name = 'JWTError';
  }
}
