import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { JWTClaims, JWTValidationResult, SupabaseConfig } from '../../types/jwt.js'
import logger from '../../utils/logger.js'

export class SupabaseJWTAuth {
  private supabase: SupabaseClient
  private config: SupabaseConfig

  constructor(config: SupabaseConfig) {
    this.config = config
    this.supabase = createClient(config.url, config.anonKey, {
      auth: {
        flowType: 'pkce',
        autoRefreshToken: true,
        persistSession: false // Server-side, no persistence needed
      }
    })
  }

  async validateJWT(jwt: string): Promise<JWTValidationResult> {
    try {
      logger.info('Validating JWT with Supabase', { jwtLength: jwt.length })
      
      // 使用Supabase的auth.getUser来验证JWT
      const { data, error } = await this.supabase.auth.getUser(jwt)
      
      if (error || !data.user) {
        logger.warn('JWT validation failed', { error: error?.message })
        return {
          valid: false,
          error: error?.message || 'Invalid JWT'
        }
      }

      logger.info('JWT validation successful', { userId: data.user.id, email: data.user.email })

      // 提取claims
      const claims: JWTClaims = {
        sub: data.user.id,
        email: data.user.email,
        iss: this.config.url,
        iat: Math.floor(Date.now() / 1000),
        'x-mcp-email': data.user.email,
        'x-mcp-category': 'supabase-jwt',
        'x-mcp-description': `Supabase user: ${data.user.email}`
      }

      return {
        valid: true,
        claims,
        accountEmail: data.user.email
      }
    } catch (error) {
      logger.error('JWT validation error:', error)
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'JWT validation error'
      }
    }
  }

  async getGoogleTokensFromSession(session: any): Promise<{ accessToken: string; refreshToken?: string } | null> {
    try {
      if (!session?.provider_token) {
        logger.warn('No provider token found in session')
        return null
      }

      return {
        accessToken: session.provider_token,
        refreshToken: session.provider_refresh_token
      }
    } catch (error) {
      logger.error('Error extracting Google tokens:', error)
      return null
    }
  }

  async getSession(jwt: string): Promise<any> {
    try {
      const { data, error } = await this.supabase.auth.getSession()
      if (error) {
        logger.error('Error getting session:', error)
        return null
      }
      return data.session
    } catch (error) {
      logger.error('Error getting session:', error)
      return null
    }
  }
}