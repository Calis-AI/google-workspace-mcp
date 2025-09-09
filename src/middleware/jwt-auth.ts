import { getAccountManager } from '../modules/accounts/index.js';
import logger from '../utils/logger.js';
import { JWTError } from '../modules/accounts/types.js';

/**
 * JWT认证中间件 - MCP规范合规版本
 * 
 * MCP规范要求：
 * 1. Token必须通过HTTP Authorization头发送
 * 2. 不能使用URI参数传输token
 * 3. 必须验证标准JWT claims
 * 4. 401响应必须包含WWW-Authenticate头
 */

// MCP标准JWT Claims
const REQUIRED_CLAIMS = ['iss', 'iat', 'exp', 'aud', 'sub'];
const OPTIONAL_CLAIMS = ['client_id', 'jti'];

/**
 * 验证JWT是否符合MCP标准claims要求
 */
function validateMCPStandardClaims(payload: any): { valid: boolean; error?: string } {
  // 检查必需claims
  for (const claim of REQUIRED_CLAIMS) {
    if (payload[claim] === undefined || payload[claim] === null) {
      return { 
        valid: false, 
        error: `Missing required JWT claim: ${claim}` 
      };
    }
  }

  // 验证时间相关claims
  const now = Math.floor(Date.now() / 1000);
  
  if (payload.exp && payload.exp < now) {
    return { 
      valid: false, 
      error: 'JWT has expired' 
    };
  }

  if (payload.nbf && payload.nbf > now) {
    return { 
      valid: false, 
      error: 'JWT not yet valid' 
    };
  }

  // 验证issuer格式
  if (payload.iss && typeof payload.iss !== 'string') {
    return { 
      valid: false, 
      error: 'Invalid issuer claim format' 
    };
  }

  // 验证audience格式
  if (payload.aud && typeof payload.aud !== 'string' && !Array.isArray(payload.aud)) {
    return { 
      valid: false, 
      error: 'Invalid audience claim format' 
    };
  }

  return { valid: true };
}

/**
 * JWT认证中间件
 * 处理通过Authorization头传递的JWT token（MCP规范要求）
 * 如果验证成功，自动创建或更新对应的账户
 */
export async function processJWTAuthentication(jwt: string): Promise<{
  success: boolean;
  account?: any;
  error?: string;
  wwwAuthenticate?: string; // 用于401响应的WWW-Authenticate头
}> {
  try {
    const accountManager = getAccountManager();
    
    // 解码JWT payload获取邮箱
    let payload: any;
    try {
      // JWT格式：header.payload.signature
      const parts = jwt.split('.');
      if (parts.length !== 3) {
        return {
          success: false,
          error: 'Invalid JWT format',
          wwwAuthenticate: 'Bearer error="invalid_token", error_description="Invalid JWT format"'
        };
      }
      
      // 解码payload部分
      const payloadPart = parts[1];
      // 添加必要的填充
      const normalized = payloadPart + '='.repeat((4 - payloadPart.length % 4) % 4);
      // 替换URL安全的base64字符
      const decoded = atob(normalized.replace(/-/g, '+').replace(/_/g, '/'));
      payload = JSON.parse(decoded);
    } catch (error) {
      logger.error('Failed to decode JWT payload', error);
      return {
        success: false,
        error: 'Invalid JWT payload',
        wwwAuthenticate: 'Bearer error="invalid_token", error_description="Invalid JWT payload"'
      };
    }

    // 验证MCP标准claims
    const claimsValidation = validateMCPStandardClaims(payload);
    if (!claimsValidation.valid) {
      return {
        success: false,
        error: claimsValidation.error,
        wwwAuthenticate: `Bearer error="invalid_token", error_description="${claimsValidation.error}"`
      };
    }

    // 从payload中提取邮箱
    const email = payload.email || payload.sub;
    if (!email) {
      return {
        success: false,
        error: 'No email found in JWT payload',
        wwwAuthenticate: 'Bearer error="invalid_token", error_description="No email in JWT"'
      };
    }

    logger.info('Processing JWT authentication', { email, issuer: payload.iss, audience: payload.aud });

    // 验证JWT并获取账户
    let account;
    try {
      // 首先验证JWT是否有效
      const validation = await accountManager.validateJWT(email, jwt);
      if (!validation.valid) {
        return {
          success: false,
          error: validation.reason || 'JWT validation failed',
          wwwAuthenticate: `Bearer error="invalid_token", error_description="${validation.reason || 'JWT validation failed'}"`
        };
      }

      // 检查账户是否已存在
      const existingAccount = await accountManager.getAccount(email);
      
      if (existingAccount) {
        // 更新现有账户的认证方式
        if (existingAccount.auth_method !== 'jwt') {
          await accountManager.updateAccount(email, {
            auth_method: 'jwt',
            category: existingAccount.category,
            description: existingAccount.description
          });
        }
        account = existingAccount;
        logger.info('Updated existing account with JWT authentication', { email });
      } else {
        // 创建新的JWT账户
        account = await accountManager.createJWTAccount(
          email, 
          jwt,
          'jwt-user',
          `JWT user: ${email}`
        );
        logger.info('Created new JWT account', { email });
      }

      return {
        success: true,
        account
      };

    } catch (error) {
      if (error instanceof JWTError) {
        return {
          success: false,
          error: error.message,
          wwwAuthenticate: `Bearer error="invalid_token", error_description="${error.message}"`
        };
      }
      
      logger.error('JWT authentication processing error', error);
      return {
        success: false,
        error: 'Authentication processing failed',
        wwwAuthenticate: 'Bearer error="server_error", error_description="Authentication processing failed"'
      };
    }

  } catch (error) {
    logger.error('Unexpected error in JWT authentication', error);
    return {
      success: false,
      error: 'Internal authentication error',
      wwwAuthenticate: 'Bearer error="server_error", error_description="Internal authentication error"'
    };
  }
}

/**
 * 从请求头中提取JWT token（MCP规范要求）
 * 
 * MCP规范要求：
 * - Token必须通过HTTP Authorization头发送
 * - 格式：Authorization: Bearer <token>
 * - 不能使用URI参数传输token
 */
export function extractJWTFromHeader(authHeader: string | undefined): string | null {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.substring(7);
}

/**
 * JWT认证结果类型 - MCP合规版本
 */
export interface JWTAuthResult {
  success: boolean;
  account?: any;
  error?: string;
  wwwAuthenticate?: string; // MCP规范要求的WWW-Authenticate头
  authMethod?: 'jwt' | 'oauth';
  mcpCompliant?: boolean; // 标记是否符合MCP规范
}