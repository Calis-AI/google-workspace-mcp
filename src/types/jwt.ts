export interface JWTConfig {
  enabled: boolean;
  jwksUri?: string;
  publicKey?: string;
  issuerWhitelist: string[];
  audience?: string;
  requireExp: boolean;
  requireIat: boolean;
  maxAge?: number; // seconds
  clockTolerance: number; // seconds
}

export interface JWTClaims {
  // Standard claims
  iss?: string; // issuer
  sub?: string; // subject
  aud?: string | string[]; // audience
  exp?: number; // expiration time
  nbf?: number; // not before
  iat?: number; // issued at
  jti?: string; // JWT ID
  
  // Custom MCP claims
  'x-mcp-email'?: string;
  'x-mcp-category'?: string;
  'x-mcp-description'?: string;
  'x-mcp-scopes'?: string[];
  'x-mcp-account-id'?: string;
  
  // Additional custom claims
  [key: string]: any;
}

export interface JWTValidationResult {
  valid: boolean;
  claims?: JWTClaims;
  error?: string;
  accountEmail?: string;
}

export interface JWTAccountMetadata {
  authMethod: 'jwt';
  jwtClaims: JWTClaims;
  jwtExpiry: number;
  issuer: string;
  subject: string;
  originalToken: string; // Store for potential refresh
}

export interface JWTTokenData {
  token: string;
  claims: JWTClaims;
  expiry: number;
  accountEmail: string;
}

export interface SupabaseConfig {
  enabled: boolean;
  url: string;
  anonKey: string;
  jwtSecret?: string;
}