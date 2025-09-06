import { TokenStatus, Account } from './types.js'
import { JWTClaims, JWTTokenData, JWTValidationResult, SupabaseConfig } from '../../types/jwt.js'
import { SupabaseJWTAuth } from './supabase-jwt-auth.js'
import logger from '../../utils/logger.js'

export class JWTTokenManager {
  private jwtAuth: SupabaseJWTAuth
  private jwtTokens: Map<string, JWTTokenData> = new Map()
  private tokenExpiryMap: Map<string, number> = new Map()

  constructor(supabaseConfig: SupabaseConfig) {
    this.jwtAuth = new SupabaseJWTAuth(supabaseConfig)
  }

  async validateJWT(email: string, jwt: string): Promise<TokenStatus> {
    try {
      logger.info('Validating JWT token', { email, jwtLength: jwt.length })
      
      // 验证JWT
      const validation = await this.jwtAuth.validateJWT(jwt)
      
      if (!validation.valid || !validation.claims) {
        logger.warn('JWT validation failed', { email, error: validation.error })
        return {
          valid: false,
          status: 'INVALID',
          reason: validation.error || 'JWT validation failed'
        }
      }

      // 检查过期时间
      const now = Math.floor(Date.now() / 1000)
      if (validation.claims.exp && validation.claims.exp < now) {
        logger.warn('JWT has expired', { email, exp: validation.claims.exp, now })
        return {
          valid: false,
          status: 'EXPIRED',
          reason: 'JWT has expired'
        }
      }

      // 存储JWT数据
      const tokenData: JWTTokenData = {
        token: jwt,
        claims: validation.claims,
        expiry: validation.claims.exp || (now + 3600), // 默认1小时
        accountEmail: validation.accountEmail!
      }

      this.jwtTokens.set(email, tokenData)
      this.tokenExpiryMap.set(email, tokenData.expiry)

      logger.info('JWT validation successful', { email, expiry: tokenData.expiry })

      return {
        valid: true,
        status: 'VALID',
        token: jwt
      }
    } catch (error) {
      logger.error('JWT token validation error:', error)
      return {
        valid: false,
        status: 'ERROR',
        reason: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }

  isJWTToken(token: any): boolean {
    if (typeof token !== 'string') {
      return false
    }
    
    // JWT格式：header.payload.signature
    const parts = token.split('.')
    if (parts.length !== 3) {
      return false
    }

    // 检查每个部分都是base64url编码
    try {
      parts.forEach(part => {
        // 添加填充并解码
        const normalized = part + '='.repeat((4 - part.length % 4) % 4)
        atob(normalized.replace(/-/g, '+').replace(/_/g, '/'))
      })
      return true
    } catch {
      return false
    }
  }

  getJWTToken(email: string): JWTTokenData | undefined {
    const tokenData = this.jwtTokens.get(email)
    
    // 检查是否过期
    if (tokenData) {
      const now = Math.floor(Date.now() / 1000)
      if (tokenData.expiry < now) {
        logger.info('JWT token expired, removing from cache', { email, expiry: tokenData.expiry, now })
        this.removeJWTToken(email)
        return undefined
      }
    }
    
    return tokenData
  }

  removeJWTToken(email: string): void {
    logger.info('Removing JWT token', { email })
    this.jwtTokens.delete(email)
    this.tokenExpiryMap.delete(email)
  }

  async getGoogleTokensFromJWT(email: string): Promise<{ accessToken: string; refreshToken?: string } | null> {
    try {
      const jwtData = this.getJWTToken(email)
      if (!jwtData) {
        logger.warn('No JWT token found for email', { email })
        return null
      }

      // 获取Supabase会话
      const session = await this.jwtAuth.getSession(jwtData.token)
      if (!session) {
        logger.warn('No Supabase session found', { email })
        return null
      }

      // 提取Google tokens
      const googleTokens = await this.jwtAuth.getGoogleTokensFromSession(session)
      if (!googleTokens) {
        logger.warn('No Google tokens found in session', { email })
        return null
      }

      logger.info('Successfully extracted Google tokens from JWT', { 
        email, 
        hasAccessToken: !!googleTokens.accessToken,
        hasRefreshToken: !!googleTokens.refreshToken 
      })

      return googleTokens
    } catch (error) {
      logger.error('Error extracting Google tokens from JWT', { email, error })
      return null
    }
  }

  // 清理过期token的定时任务
  cleanupExpiredTokens(): void {
    const now = Math.floor(Date.now() / 1000)
    let cleanedCount = 0

    for (const [email, expiry] of this.tokenExpiryMap.entries()) {
      if (expiry < now) {
        this.removeJWTToken(email)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info('Cleaned up expired JWT tokens', { count: cleanedCount })
    }
  }

  // 获取所有JWT token的统计信息
  getStats(): { totalTokens: number; expiredTokens: number } {
    const now = Math.floor(Date.now() / 1000)
    let expiredCount = 0

    for (const expiry of this.tokenExpiryMap.values()) {
      if (expiry < now) {
        expiredCount++
      }
    }

    return {
      totalTokens: this.jwtTokens.size,
      expiredTokens: expiredCount
    }
  }
}