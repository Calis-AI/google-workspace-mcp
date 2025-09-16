import logger from '../../utils/logger.js';
import { AccountError, TokenRenewalResult, TokenStatus } from './types.js';
import { FileTokenStore, TokenPayload } from './token-store.js';
import { BackendTokenRefresher } from './token-refresher.js';

export class DelegatedTokenManager {
  private readonly store = new FileTokenStore('delegated');
  private readonly refresher = new BackendTokenRefresher();
  private readonly TOKEN_EXPIRY_BUFFER_MS = Number(1000);

  async saveToken(email: string, tokenData: any): Promise<void> {
    const token: TokenPayload = {
      access_token: tokenData.access_token,
      expiry_date: typeof tokenData.expiry_date === 'number' && tokenData.expiry_date < 1_000_000_000_000
        ? tokenData.expiry_date * 1000
        : tokenData.expiry_date,
      token_type: tokenData.token_type || 'Bearer',
      scope: Array.isArray(tokenData.scope) ? tokenData.scope.join(' ') : tokenData.scope,
    };

    if (!token.access_token || !token.expiry_date) {
      throw new AccountError('Invalid token payload', 'INVALID_TOKEN', 'Provide access_token and expiry_date');
    }

    if (tokenData.refresh_token) {
      logger.warn('Delegated mode: ignoring provided refresh_token');
    }

    await this.store.save(email, token);
    logger.info(`Token saved for ${email}`);
  }

  async loadToken(email: string): Promise<TokenPayload | null> {
    return this.store.load(email);
  }

  async deleteToken(email: string): Promise<void> {
    await this.store.delete(email);
  }

  async autoRenewToken(email: string): Promise<TokenRenewalResult> {
    const token = await this.store.load(email);
    if (!token) {
      return { success: false, status: 'NO_TOKEN', reason: 'No in-memory token found' };
    }

    const now = Date.now();
    if (token.expiry_date > now + this.TOKEN_EXPIRY_BUFFER_MS) {
      return { success: true, status: 'VALID', token };
    }

    try {
      const scopes = token.scope ? token.scope.split(' ') : undefined;
      const newToken = await this.refresher.refresh(email, scopes);
      await this.store.save(email, newToken);
      logger.info('Token refreshed from backend successfully');
      return { success: true, status: 'REFRESHED', token: newToken };
    } catch (err) {
      if (err instanceof AccountError && err.code === 'AUTH_REQUIRED') {
        return { success: false, status: 'REFRESH_FAILED', reason: err.message, canRetry: false };
      }
      return { success: false, status: 'REFRESH_FAILED', reason: (err as Error)?.message || 'Refresh failed', canRetry: true };
    }
  }

  async validateToken(email: string, _skipValidationForNew: boolean = false): Promise<TokenStatus> {
    const token = await this.store.load(email);
    if (!token) {
      return { valid: false, status: 'NO_TOKEN', reason: 'No token found' };
    }

    // In delegated mode, do not call Google token introspection; rely on expiry and 401 handling

    if (token.expiry_date <= Date.now()) {
       logger.info(`Token expiry date: ${token.expiry_date} now expired: ${token.expiry_date}`);
      const renew = await this.autoRenewToken(email);
      if (renew.success && renew.token) {
        return { valid: true, status: 'REFRESHED', token: renew.token, requiredScopes: renew.token.scope ? renew.token.scope.split(' ') : undefined };
      }
      return { valid: false, status: 'EXPIRED', reason: 'Token expired and refresh failed' };
    }

    return { valid: true, status: 'VALID', token, requiredScopes: token.scope ? token.scope.split(' ') : undefined };
  }
}
