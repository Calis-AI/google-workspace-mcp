import https from 'https';
import http from 'http';
import { URL } from 'url';
import logger from '../../utils/logger.js';
import { AccountError } from './types.js';
import { TokenPayload } from './token-store.js';

export interface TokenRefresher {
  refresh(email: string, scopes?: string[]): Promise<TokenPayload>;
}

function httpPostJson(urlString: string, body: any, headers: Record<string, string>, timeoutMs: number): Promise<{ status: number; json: any; }> {
  const url = new URL(urlString);
  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;

  const payload = Buffer.from(JSON.stringify(body));
  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    'Content-Length': String(payload.length),
    ...headers,
  };

  return new Promise((resolve, reject) => {
    const req = lib.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: 'POST',
      headers: requestHeaders,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8');
        let json: any = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch (e) {
          json = null;
        }
        resolve({ status: res.statusCode || 0, json });
      });
    });

    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('Request timeout'));
    });

    req.write(payload);
    req.end();
  });
}

export class BackendTokenRefresher implements TokenRefresher {
  private url: string;
  private headers: Record<string, string>;
  private timeoutMs: number;
  private retries: number;

  constructor() {
    const url = process.env.REFRESH_TOKEN_URL || 'http://127.0.0.1:8000/api/v1/user/refresh_token';
    this.url = url;
    this.headers = {};
    if (process.env.REFRESH_AUTH_HEADER) {
      this.headers['Authorization'] = process.env.REFRESH_AUTH_HEADER;
    }
    this.timeoutMs = Number(process.env.REFRESH_TIMEOUT_MS || 8000);
    this.retries = Number(process.env.REFRESH_RETRY_COUNT || 1);
  }

  async refresh(email: string, scopes?: string[]): Promise<TokenPayload> {
    const body = { email, scopes };

    const attempt = async (): Promise<TokenPayload> => {
      logger.info(`Refreshing access token from backend for ${email}`);
      const { status, json } = await httpPostJson(this.url, body, this.headers, this.timeoutMs);

      if (status === 401 || status === 403) {
        throw new AccountError(
          'Backend refused refresh: auth required',
          'AUTH_REQUIRED',
          'Please re-authorize this account or update backend credentials'
        );
      }
      if (status >= 500 || status === 0) {
        throw new AccountError(
          `Backend refresh temporary error (status ${status})`,
          'TEMP_REFRESH_ERROR',
          'Try again shortly'
        );
      }
      if (status < 200 || status >= 300) {
        throw new AccountError(
          `Backend refresh failed (status ${status})`,
          'REFRESH_FAILED',
          'Check backend /refresh_token implementation'
        );
      }

      if (!json || !json.access_token) {
        throw new AccountError(
          'Invalid refresh response: missing access_token',
          'REFRESH_RESPONSE_ERROR',
          'Ensure backend returns access_token and expiry'
        );
      }

      let expiryMs = json.expiry_date as number | undefined;
      if (!expiryMs && typeof json.expires_in === 'number') {
        expiryMs = Date.now() + json.expires_in * 1000;
      }
      if (!expiryMs) {
        throw new AccountError(
          'Invalid refresh response: missing expiry',
          'REFRESH_RESPONSE_ERROR',
          'Provide expires_in or expiry_date'
        );
      }

      const scope = Array.isArray(json.scope) ? json.scope.join(' ') : json.scope;
      const token: TokenPayload = {
        access_token: json.access_token,
        expiry_date: expiryMs,
        token_type: json.token_type || 'Bearer',
        scope,
      };
      return token;
    };

    let lastErr: unknown;
    for (let i = 0; i <= this.retries; i++) {
      try {
        return await attempt();
      } catch (err) {
        lastErr = err;
        if (err instanceof AccountError && (err.code === 'AUTH_REQUIRED' || err.code === 'REFRESH_RESPONSE_ERROR' || err.code === 'REFRESH_FAILED')) {
          throw err; // Non-retryable here
        }
        logger.warn(`Backend refresh attempt ${i + 1} failed: ${err instanceof Error ? err.message : String(err)}`);
        if (i === this.retries) break;
        await new Promise(r => setTimeout(r, 300 * (i + 1)));
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('Unknown refresh error');
  }
}
