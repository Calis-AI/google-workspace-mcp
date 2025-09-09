import { getAccountManager } from '../modules/accounts/index.js';
import { McpToolResponse, BaseToolArguments } from './types.js';
import path from 'path';

/**
 * Lists all configured Google Workspace accounts and their authentication status
 * @returns List of accounts with their configuration and auth status
 * @throws {McpError} If account manager fails to retrieve accounts
 */
export async function handleListWorkspaceAccounts(): Promise<McpToolResponse> {
  const accounts = await getAccountManager().listAccounts();
  
  // Filter out sensitive token data before returning to AI
  const sanitizedAccounts = accounts.map(account => ({
    ...account,
    auth_status: account.auth_status ? {
      valid: account.auth_status.valid,
      status: account.auth_status.status,
      reason: account.auth_status.reason,
      authUrl: account.auth_status.authUrl
    } : undefined
  }));

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(sanitizedAccounts, null, 2)
    }]
  };
}

export interface AuthenticateAccountArgs extends BaseToolArguments {
  category?: string;
  description?: string;
  auth_code?: string;
  auto_complete?: boolean;
}

/**
 * Authenticates a Google Workspace account through OAuth2
 * @param args.email - Email address to authenticate
 * @param args.category - Optional account category (e.g., 'work', 'personal')
 * @param args.description - Optional account description
 * @param args.auth_code - OAuth2 authorization code (optional for manual flow)
 * @param args.auto_complete - Whether to automatically complete auth (default: true)
 * @returns Auth URL and instructions for completing authentication
 * @throws {McpError} If validation fails or OAuth flow errors
 */
export async function handleAuthenticateWorkspaceAccount(args: AuthenticateAccountArgs): Promise<McpToolResponse> {
  const accountManager = getAccountManager();

  // Validate/create account
  await accountManager.validateAccount(args.email, args.category, args.description);

  // If auth code is provided (manual fallback), complete the OAuth flow
  if (args.auth_code) {
    const tokenData = await accountManager.getTokenFromCode(args.auth_code);
    await accountManager.saveToken(args.email, tokenData);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'success',
          message: 'Authentication successful! Token saved. Please retry your request.'
        }, null, 2)
      }]
    };
  }

  // Generate OAuth URL and track which account is being authenticated
  const authUrl = await accountManager.startAuthentication(args.email);
  
  // Check if we should use automatic completion (default: true)
  const useAutoComplete = args.auto_complete !== false;
  
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        status: 'auth_required',
        auth_url: authUrl,
        message: 'Please complete Google OAuth authentication:',
        instructions: useAutoComplete ? [
          '1. Click the authorization URL to open Google sign-in in your browser',
          '2. Sign in with your Google account and allow the requested permissions',
          '3. Authentication will complete automatically - you can start using the account immediately'
        ].join('\n') : [
          '1. Click the authorization URL below to open Google sign-in in your browser',
          '2. Sign in with your Google account and allow the requested permissions',
          '3. After authorization, you will see a success page with your authorization code',
          '4. Copy the authorization code from the success page',
          '5. Call this tool again with the auth_code parameter: authenticate_workspace_account with auth_code="your_code_here"'
        ].join('\n'),
        note: useAutoComplete 
          ? 'The callback server will automatically complete authentication in the background.'
          : 'The callback server is running on localhost:8080 and will display your authorization code for easy copying.',
        auto_complete_enabled: useAutoComplete
      }, null, 2)
    }]
  };
}

/**
 * Completes OAuth authentication automatically by waiting for callback
 * @param args.email - Email address to authenticate
 * @returns Success message when authentication completes
 * @throws {McpError} If authentication times out or fails
 */
export async function handleCompleteWorkspaceAuth(args: BaseToolArguments): Promise<McpToolResponse> {
  const accountManager = getAccountManager();
  
  try {
    // Wait for the authorization code from the callback server
    const code = await accountManager.waitForAuthorizationCode();
    
    // Exchange code for tokens
    const tokenData = await accountManager.getTokenFromCode(code);
    await accountManager.saveToken(args.email, tokenData);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'success',
          message: 'Authentication completed automatically! Your account is now ready to use.'
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'error',
          message: 'Authentication timeout or error. Please use the manual authentication flow.',
          error: error instanceof Error ? error.message : 'Unknown error'
        }, null, 2)
      }]
    };
  }
}

/**
 * Removes a Google Workspace account and its associated authentication tokens
 * @param args.email - Email address of the account to remove
 * @returns Success message if account removed
 * @throws {McpError} If account removal fails
 */
export async function handleRemoveWorkspaceAccount(args: BaseToolArguments): Promise<McpToolResponse> {
  await getAccountManager().removeAccount(args.email);
  
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        status: 'success',
        message: `Successfully removed account ${args.email} and deleted associated tokens`
      }, null, 2)
    }]
  };
}

export interface SetAccountTokenArgs extends BaseToolArguments {
  category?: string;
  description?: string;
  token: {
    access_token: string;
    refresh_token?: string;
    expiry_date: number; // ms
    token_type?: string;
    scope?: string | string[];
  };
  validate?: boolean;
}

function resolvePaths() {
  const accountsPath =
    process.env.ACCOUNTS_PATH ||
    (process.env.MCP_MODE
      ? path.resolve(process.env.HOME || '', '.mcp/google-workspace-mcp/accounts.json')
      : '/app/config/accounts.json');
  const credentialsPath =
    process.env.CREDENTIALS_PATH ||
    (process.env.MCP_MODE
      ? path.resolve(process.env.HOME || '', '.mcp/google-workspace-mcp/credentials')
      : '/app/config/credentials');
  return { accountsPath, credentialsPath };
}

function sanitizeAccount(account: any) {
  if (!account) return null;
  const auth = account.auth_status || {};
  return {
    email: account.email,
    category: account.category,
    description: account.description,
    auth_status: {
      valid: Boolean(auth?.valid),
      status: auth?.status,
      reason: auth?.reason,
      authUrl: auth?.authUrl,
    },
  };
}

export async function handleSetWorkspaceAccountToken(args: SetAccountTokenArgs): Promise<any> {
  const accountManager = getAccountManager();
  const email = args.email;
  const category = args.category ?? 'work';
  const description = args.description ?? 'Work Account';

  // Normalize token payload
  const token: any = { ...(args.token || {}) };
  if (!token.token_type) token.token_type = 'Bearer';
  if (typeof token.expiry_date === 'number' && token.expiry_date < 1_000_000_000_000) {
    token.expiry_date = token.expiry_date * 1000; // seconds -> ms
  }
  if (Array.isArray(token.scope)) {
    token.scope = token.scope.join(' ');
  }

  // Ensure account exists and save token
  await accountManager.validateAccount(email, category, description);
  await accountManager.saveToken(email, token);

  let account = null;
  if (args.validate !== false) {
    account = await accountManager.validateAccount(email);
  } else {
    account = await accountManager.getAccount(email);
  }

  const { accountsPath, credentialsPath } = resolvePaths();
  const warnings: string[] = [];
  if (!token.refresh_token) warnings.push('No refresh_token provided - token will expire');
  if (typeof token.expiry_date === 'number' && token.expiry_date - Date.now() <= 5 * 60 * 1000) {
    warnings.push('Token expires soon (<=5 minutes) - will require refresh');
  }

  return {
    status: 'success',
    account: sanitizeAccount(account),
    paths: {
      accountsPath,
      credentialsPath,
      env: {
        MCP_MODE: process.env.MCP_MODE || '',
        ACCOUNTS_PATH: process.env.ACCOUNTS_PATH || '',
        CREDENTIALS_PATH: process.env.CREDENTIALS_PATH || '',
        GOOGLE_CLIENT_ID: Boolean(process.env.GOOGLE_CLIENT_ID),
        GOOGLE_CLIENT_SECRET: Boolean(process.env.GOOGLE_CLIENT_SECRET),
      },
    },
    warnings,
  };
}

export async function handleGetWorkspaceConfig(): Promise<any> {
  const { accountsPath, credentialsPath } = resolvePaths();
  return {
    status: 'success',
    paths: {
      accountsPath,
      credentialsPath,
    },
    env: {
      MCP_MODE: process.env.MCP_MODE || '',
      ACCOUNTS_PATH: process.env.ACCOUNTS_PATH || '',
      CREDENTIALS_PATH: process.env.CREDENTIALS_PATH || '',
      GOOGLE_CLIENT_ID: Boolean(process.env.GOOGLE_CLIENT_ID),
      GOOGLE_CLIENT_SECRET: Boolean(process.env.GOOGLE_CLIENT_SECRET),
      HOME: process.env.HOME || '',
    },
  };
}
