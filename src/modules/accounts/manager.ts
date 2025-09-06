import fs from 'fs/promises';
import path from 'path';
import {Account, AccountsConfig, AccountError, JWTError, AccountModuleConfig, TokenStatus} from './types.js';
import { scopeRegistry } from '../tools/scope-registry.js';
import { TokenManager } from './token.js';
import { JWTTokenManager } from './jwt-token-manager.js';
import { GoogleOAuthClient } from './oauth.js';
import { SupabaseConfig } from '../../types/jwt.js';
import logger from '../../utils/logger.js';

export class AccountManager {
  private readonly accountsPath: string;
  private accounts: Map<string, Account>;
  private tokenManager!: TokenManager;
  private jwtTokenManager?: JWTTokenManager;
  private oauthClient!: GoogleOAuthClient;
  private currentAuthEmail?: string;
  private supabaseConfig?: SupabaseConfig;
  // 新增：内部JWT缓存（工具无感知）
  private jwtAuthCache: Map<string, {jwt: string, expiry: number}> = new Map();

  constructor(config?: AccountModuleConfig) {
    // Use environment variable or config, fallback to Docker default
    const defaultPath = process.env.ACCOUNTS_PATH || 
                       (process.env.MCP_MODE ? path.resolve(process.env.HOME || '', '.mcp/google-workspace-mcp/accounts.json') : '/app/config/accounts.json');
    this.accountsPath = config?.accountsPath || defaultPath;
    this.accounts = new Map();
    
    // 初始化Supabase配置
    if (config?.supabaseConfig?.enabled && config.supabaseConfig.url && config.supabaseConfig.anonKey) {
      this.supabaseConfig = {
        enabled: config.supabaseConfig.enabled,
        url: config.supabaseConfig.url,
        anonKey: config.supabaseConfig.anonKey,
        jwtSecret: config.supabaseConfig.jwtSecret
      };
      logger.info('Supabase JWT authentication enabled');
    }
  }

  async initialize(): Promise<void> {
    logger.info('Initializing AccountManager...');
    this.oauthClient = new GoogleOAuthClient();
    this.tokenManager = new TokenManager(this.oauthClient);
    
    // 初始化JWT Token Manager（如果启用了Supabase）
    if (this.supabaseConfig?.enabled) {
      this.jwtTokenManager = new JWTTokenManager(this.supabaseConfig);
      logger.info('JWT Token Manager initialized for Supabase authentication');
    }
    
    // Set up automatic authentication completion
    const { OAuthCallbackServer } = await import('./callback-server.js');
    const callbackServer = OAuthCallbackServer.getInstance();
    callbackServer.setAuthHandler(async (code: string) => {
      if (this.currentAuthEmail) {
        try {
          logger.info(`Auto-completing authentication for ${this.currentAuthEmail}`);
          const tokenData = await this.getTokenFromCode(code);
          await this.saveToken(this.currentAuthEmail, tokenData);
          logger.info(`Authentication completed automatically for ${this.currentAuthEmail}`);
          this.currentAuthEmail = undefined;
        } catch (error) {
          logger.error('Failed to auto-complete authentication:', error);
          this.currentAuthEmail = undefined;
        }
      }
    });
    
    await this.loadAccounts();
    logger.info('AccountManager initialized successfully');
  }

  async listAccounts(): Promise<Account[]> {
    logger.debug('Listing accounts with auth status');
    const accounts = Array.from(this.accounts.values());
    
    // Add auth status to each account and attempt auto-renewal if needed
    for (const account of accounts) {
      const renewalResult = await this.tokenManager.autoRenewToken(account.email);
      
      if (renewalResult.success) {
        account.auth_status = {
          valid: true,
          status: renewalResult.status
        };
      } else {
        // If auto-renewal failed, try to get an auth URL for re-authentication
        account.auth_status = {
          valid: false,
          status: renewalResult.status,
          reason: renewalResult.reason,
          authUrl: await this.generateAuthUrl()
        };
      }
    }
    
    logger.debug(`Found ${accounts.length} accounts`);
    return accounts;
  }

  /**
   * Wrapper for tool operations that handles token renewal
   * @param email Account email
   * @param operation Function that performs the actual operation
   */
  async withTokenRenewal<T>(
    email: string,
    operation: () => Promise<T>
  ): Promise<T> {
    try {
      // Attempt auto-renewal before operation
      const renewalResult = await this.tokenManager.autoRenewToken(email);
      if (!renewalResult.success) {
        if (renewalResult.canRetry) {
          // If it's a temporary error, let the operation proceed
          // The 401 handler below will catch and retry if needed
          logger.warn('Token renewal failed but may be temporary - proceeding with operation');
        } else {
          // Only require re-auth if refresh token is invalid/revoked
          throw new AccountError(
            'Token renewal failed',
            'TOKEN_RENEWAL_FAILED',
            renewalResult.reason || 'Please re-authenticate your account'
          );
        }
      }

      // Perform the operation
      return await operation();
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === '401') {
        // If we get a 401 during operation, try one more token renewal
        logger.warn('Received 401 during operation, attempting final token renewal');
        const finalRenewal = await this.tokenManager.autoRenewToken(email);
        
        if (finalRenewal.success) {
          // Retry the operation with renewed token
          return await operation();
        }
        
        // Check if we should trigger full OAuth
        if (!finalRenewal.canRetry) {
          // Refresh token is invalid/revoked, need full reauth
          throw new AccountError(
            'Authentication failed',
            'AUTH_REQUIRED',
            finalRenewal.reason || 'Please re-authenticate your account'
          );
        } else {
          // Temporary error, let caller handle retry
          throw new AccountError(
            'Token refresh failed temporarily',
            'TEMPORARY_AUTH_ERROR',
            'Please try again later'
          );
        }
      }
      throw error;
    }
  }

  private validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private async loadAccounts(): Promise<void> {
    try {
      logger.debug(`Loading accounts from ${this.accountsPath}`);
      // Ensure directory exists
      await fs.mkdir(path.dirname(this.accountsPath), { recursive: true });
      
      let data: string;
      try {
        data = await fs.readFile(this.accountsPath, 'utf-8');
      } catch (error) {
        if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
          // Create empty accounts file if it doesn't exist
          logger.info('Creating new accounts file');
          data = JSON.stringify({ accounts: [] });
          await fs.writeFile(this.accountsPath, data);
        } else {
          throw new AccountError(
            'Failed to read accounts configuration',
            'ACCOUNTS_READ_ERROR',
            'Please ensure the accounts file is readable'
          );
        }
      }

      try {
        const config = JSON.parse(data) as AccountsConfig;
        this.accounts.clear();
        for (const account of config.accounts) {
          this.accounts.set(account.email, account);
        }
      } catch (error) {
        throw new AccountError(
          'Failed to parse accounts configuration',
          'ACCOUNTS_PARSE_ERROR',
          'Please ensure the accounts file contains valid JSON'
        );
      }
    } catch (error) {
      if (error instanceof AccountError) {
        throw error;
      }
      throw new AccountError(
        'Failed to load accounts configuration',
        'ACCOUNTS_LOAD_ERROR',
        'Please ensure accounts.json exists and is valid'
      );
    }
  }

  private async saveAccounts(): Promise<void> {
    try {
      const config: AccountsConfig = {
        accounts: Array.from(this.accounts.values())
      };
      await fs.writeFile(
        this.accountsPath,
        JSON.stringify(config, null, 2)
      );
    } catch (error) {
      throw new AccountError(
        'Failed to save accounts configuration',
        'ACCOUNTS_SAVE_ERROR',
        'Please ensure accounts.json is writable'
      );
    }
  }

  async addAccount(email: string, category: string, description: string): Promise<Account> {
    logger.info(`Adding new account: ${email}`);
    if (!this.validateEmail(email)) {
      logger.error(`Invalid email format: ${email}`);
      throw new AccountError(
        'Invalid email format',
        'INVALID_EMAIL',
        'Please provide a valid email address'
      );
    }

    if (this.accounts.has(email)) {
      throw new AccountError(
        'Account already exists',
        'DUPLICATE_ACCOUNT',
        'Use updateAccount to modify existing accounts'
      );
    }

    const account: Account = {
      email,
      category,
      description
    };

    this.accounts.set(email, account);
    await this.saveAccounts();
    return account;
  }

  async updateAccount(email: string, updates: Partial<Omit<Account, 'email'>>): Promise<Account> {
    const account = this.accounts.get(email);
    if (!account) {
      throw new AccountError(
        'Account not found',
        'ACCOUNT_NOT_FOUND',
        'Please ensure the account exists before updating'
      );
    }

    const updatedAccount: Account = {
      ...account,
      ...updates
    };

    this.accounts.set(email, updatedAccount);
    await this.saveAccounts();
    return updatedAccount;
  }

  async removeAccount(email: string): Promise<void> {
    logger.info(`Removing account: ${email}`);
    if (!this.accounts.has(email)) {
      logger.error(`Account not found: ${email}`);
      throw new AccountError(
        'Account not found',
        'ACCOUNT_NOT_FOUND',
        'Cannot remove non-existent account'
      );
    }

    // Delete token first
    await this.tokenManager.deleteToken(email);
    
    // Then remove account
    this.accounts.delete(email);
    await this.saveAccounts();
    logger.info(`Successfully removed account: ${email}`);
  }

  async getAccount(email: string): Promise<Account | null> {
    return this.accounts.get(email) || null;
  }

  async validateAccount(
    email: string,
    category?: string,
    description?: string
  ): Promise<Account> {
    logger.debug(`Validating account: ${email}`);
    let account = await this.getAccount(email);
    const isNewAccount: boolean = Boolean(!account && category && description);

    try {
      // Handle new account creation
      if (isNewAccount && category && description) {
        logger.info('Creating new account during validation');
        account = await this.addAccount(email, category, description);
      } else if (!account) {
        throw new AccountError(
          'Account not found',
          'ACCOUNT_NOT_FOUND',
          'Please provide category and description for new accounts'
        );
      }

      // Validate token with appropriate flags for new accounts
      const tokenStatus = await this.tokenManager.validateToken(email, isNewAccount);
      
      // Map token status to account auth status
      switch (tokenStatus.status) {
        case 'NO_TOKEN':
          account.auth_status = {
            valid: false,
            status: tokenStatus.status,
            reason: isNewAccount ? 'New account requires authentication' : 'No token found',
            authUrl: await this.generateAuthUrl()
          };
          break;
          
        case 'VALID':
        case 'REFRESHED':
          account.auth_status = {
            valid: true,
            status: tokenStatus.status
          };
          break;
          
        case 'INVALID':
        case 'REFRESH_FAILED':
        case 'EXPIRED':
          account.auth_status = {
            valid: false,
            status: tokenStatus.status,
            reason: tokenStatus.reason,
            authUrl: await this.generateAuthUrl()
          };
          break;
          
        case 'ERROR':
          account.auth_status = {
            valid: false,
            status: tokenStatus.status,
            reason: 'Authentication error occurred',
            authUrl: await this.generateAuthUrl()
          };
          break;
      }

      logger.debug(`Account validation complete for ${email}. Status: ${tokenStatus.status}`);
      return account;
      
    } catch (error) {
      logger.error('Account validation failed', error as Error);
      if (error instanceof AccountError) {
        throw error;
      }
      throw new AccountError(
        'Account validation failed',
        'VALIDATION_ERROR',
        'An unexpected error occurred during account validation'
      );
    }
  }

  // OAuth related methods
  async generateAuthUrl(): Promise<string> {
    const allScopes = scopeRegistry.getAllScopes();
    return this.oauthClient.generateAuthUrl(allScopes);
  }
  
  async startAuthentication(email: string): Promise<string> {
    this.currentAuthEmail = email;
    logger.info(`Starting authentication for ${email}`);
    return this.generateAuthUrl();
  }

  async waitForAuthorizationCode(): Promise<string> {
    return this.oauthClient.waitForAuthorizationCode();
  }

  async getTokenFromCode(code: string): Promise<any> {
    const token = await this.oauthClient.getTokenFromCode(code);
    return token;
  }

  async refreshToken(refreshToken: string): Promise<any> {
    return this.oauthClient.refreshToken(refreshToken);
  }

  async getAuthClient() {
    return this.oauthClient.getAuthClient();
  }

  // Token related methods
  async validateToken(email: string, skipValidationForNew: boolean = false) {
    // 获取账户信息
    const account = this.accounts.get(email);
    if (!account) {
      return {
        valid: false,
        status: 'NOT_FOUND' as const,
        reason: 'Account not found'
      };
    }

    // 获取当前token
    const tokenData = await this.tokenManager.getToken(email);
    if (!tokenData) {
      return {
        valid: false,
        status: 'NO_TOKEN' as const,
        reason: 'No token found'
      };
    }

    // 判断token类型并验证
    if (this.jwtTokenManager?.isJWTToken(tokenData.access_token)) {
      // JWT token验证
      return await this.jwtTokenManager.validateJWT(email, tokenData.access_token);
    } else {
      // OAuth token验证（现有逻辑）
      return await this.tokenManager.validateToken(email, skipValidationForNew);
    }
  }

  async saveToken(email: string, tokenData: any) {
    // 检查是否是JWT token
    if (this.jwtTokenManager?.isJWTToken(tokenData.access_token || tokenData)) {
      // JWT token不需要保存到文件，只存储在内存中
      const jwt = tokenData.access_token || tokenData;
      const validation = await this.jwtTokenManager.validateJWT(email, jwt);
      if (validation.valid) {
        // 更新账户认证方式
        const account = this.accounts.get(email);
        if (account) {
          account.auth_method = 'jwt';
          account.jwt_metadata = {
            provider: 'supabase',
            claims: validation.claims,
            expiry: validation.claims?.exp
          };
          await this.saveAccounts();
        }
        return validation;
      }
      throw new JWTError('Invalid JWT token', 'INVALID_JWT', 'Please provide a valid JWT token');
    }
    
    // OAuth token保存（现有逻辑）
    return await this.tokenManager.saveToken(email, tokenData);
  }

  // JWT相关新方法
  async validateJWT(email: string, jwt: string): Promise<TokenStatus> {
    if (!this.jwtTokenManager) {
      throw new JWTError('JWT authentication not enabled', 'JWT_NOT_ENABLED', 'Please configure Supabase authentication');
    }
    
    return await this.jwtTokenManager.validateJWT(email, jwt);
  }

  async createJWTAccount(email: string, jwt: string, category?: string, description?: string): Promise<Account> {
    if (!this.jwtTokenManager) {
      throw new JWTError('JWT authentication not enabled', 'JWT_NOT_ENABLED', 'Please configure Supabase authentication');
    }

    logger.info(`Creating JWT account: ${email}`);
    
    // 验证JWT
    const validation = await this.jwtTokenManager.validateJWT(email, jwt);
    if (!validation.valid) {
      throw new JWTError('Invalid JWT token', 'INVALID_JWT', validation.reason || 'JWT validation failed');
    }

    // 检查账户是否已存在
    if (this.accounts.has(email)) {
      const existingAccount = this.accounts.get(email)!;
      // 更新为JWT认证方式
      existingAccount.auth_method = 'jwt';
      existingAccount.jwt_metadata = {
        provider: 'supabase',
        claims: validation.claims,
        expiry: validation.claims?.exp
      };
      existingAccount.category = category || existingAccount.category;
      existingAccount.description = description || existingAccount.description;
      
      await this.saveAccounts();
      logger.info(`Updated existing account to JWT authentication: ${email}`);
      return existingAccount;
    }

    // 创建新账户
    const account: Account = {
      email,
      category: category || 'jwt-user',
      description: description || `JWT user: ${email}`,
      auth_method: 'jwt',
      jwt_metadata: {
        provider: 'supabase',
        claims: validation.claims,
        expiry: validation.claims?.exp
      }
    };

    this.accounts.set(email, account);
    await this.saveAccounts();
    logger.info(`Created new JWT account: ${email}`);
    return account;
  }

  async getGoogleTokensFromJWT(email: string): Promise<{ accessToken: string; refreshToken?: string } | null> {
    if (!this.jwtTokenManager) {
      return null;
    }
    
    return await this.jwtTokenManager.getGoogleTokensFromJWT(email);
  }

  // ===== 内部JWT缓存机制（工具无感知） =====
  
  /**
   * 内部JWT缓存方法 - 用于MCP集成
   * 缓存JWT token，供后续工具调用使用
   * @param email 账户邮箱
   * @param jwt JWT token
   * @returns 是否缓存成功
   */
  async cacheJWT(email: string, jwt: string): Promise<boolean> {
    if (!this.jwtTokenManager) {
      logger.warn('JWT authentication not enabled, cannot cache JWT', { email });
      return false;
    }
    
    try {
      logger.info('Caching JWT for account', { email, jwtLength: jwt.length });
      
      // 验证JWT有效性
      const validation = await this.jwtTokenManager.validateJWT(email, jwt);
      if (!validation.valid) {
        logger.warn('Invalid JWT, not caching', { email, error: validation.reason });
        return false;
      }
      
      // 缓存JWT（1小时有效期）
      const expiry = Date.now() + 3600000; // 1小时
      this.jwtAuthCache.set(email, { jwt, expiry });
      
      logger.info('JWT cached successfully', { email, expiry });
      return true;
      
    } catch (error) {
      logger.error('Failed to cache JWT', { email, error });
      return false;
    }
  }
  
  /**
   * 获取缓存的JWT
   * @param email 账户邮箱
   * @returns JWT token 或 null
   */
  private getCachedJWT(email: string): string | null {
    const cached = this.jwtAuthCache.get(email);
    if (!cached) {
      return null;
    }
    
    // 检查是否过期
    const now = Date.now();
    if (cached.expiry < now) {
      logger.info('Cached JWT expired, removing', { email, expiry: cached.expiry, now });
      this.jwtAuthCache.delete(email);
      return null;
    }
    
    return cached.jwt;
  }
  
  /**
   * 清理过期的JWT缓存
   */
  private cleanupExpiredJWTCache(): void {
    const now = Date.now();
    let removedCount = 0;
    
    for (const [email, data] of this.jwtAuthCache.entries()) {
      if (data.expiry < now) {
        this.jwtAuthCache.delete(email);
        removedCount++;
      }
    }
    
    if (removedCount > 0) {
      logger.info('Cleaned up expired JWT cache', { removedCount });
    }
  }
  
  /**
   * 智能Token验证 - 优先使用JWT缓存，回退到OAuth
   * @param email 账户邮箱
   * @param skipValidationForNew 是否跳过新账户验证
   * @returns Token验证结果
   */
  async validateToken(email: string, skipValidationForNew: boolean = false): Promise<TokenStatus> {
    // 清理过期缓存
    this.cleanupExpiredJWTCache();
    
    // 获取账户信息
    const account = this.accounts.get(email);
    if (!account) {
      return {
        valid: false,
        status: 'NOT_FOUND' as const,
        reason: 'Account not found'
      };
    }
    
    // 优先检查JWT缓存（工具无感知的JWT认证）
    const cachedJWT = this.getCachedJWT(email);
    if (cachedJWT && this.jwtTokenManager) {
      logger.info('Using cached JWT for validation', { email });
      return await this.jwtTokenManager.validateJWT(email, cachedJWT);
    }
    
    // 回退到现有的token验证逻辑（OAuth）
    return await this.existingValidateToken(email, skipValidationForNew);
  }
  
  /**
   * 原有的Token验证逻辑（重命名避免递归）
   */
  private async existingValidateToken(email: string, skipValidationForNew: boolean = false): Promise<TokenStatus> {
    // 获取当前token
    const tokenData = await this.tokenManager.getToken(email);
    if (!tokenData) {
      return {
        valid: false,
        status: 'NO_TOKEN' as const,
        reason: 'No token found'
      };
    }
    
    // 判断token类型并验证
    if (this.jwtTokenManager?.isJWTToken(tokenData.access_token)) {
      // JWT token验证（来自文件存储）
      return await this.jwtTokenManager.validateJWT(email, tokenData.access_token);
    } else {
      // OAuth token验证（现有逻辑）
      return await this.tokenManager.validateToken(email, skipValidationForNew);
    }
  }
}
