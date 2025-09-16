import fs from 'fs/promises';
import path from 'path';

export interface TokenPayload {
  access_token: string;
  expiry_date: number; // ms since epoch
  token_type?: string;
  scope?: string;
}

export interface TokenStore {
  save(email: string, token: TokenPayload): Promise<void>;
  load(email: string): Promise<TokenPayload | null>;
  delete(email: string): Promise<void>;
}

export class InMemoryTokenStore implements TokenStore {
  private store = new Map<string, TokenPayload>();

  async save(email: string, token: TokenPayload): Promise<void> {
    this.store.set(email, token);
  }

  async load(email: string): Promise<TokenPayload | null> {
    return this.store.get(email) || null;
  }

  async delete(email: string): Promise<void> {
    this.store.delete(email);
  }
}

export class FileTokenStore implements TokenStore {
  private basePath: string;

  constructor(subdir?: string) {
    const defaultBase =
      process.env.CREDENTIALS_PATH ||
      (process.env.MCP_MODE
        ? path.resolve(process.env.HOME || '', '.mcp/google-workspace-mcp/credentials')
        : '/app/config/credentials');
    this.basePath = subdir ? path.join(defaultBase, subdir) : defaultBase;
  }

  private tokenPath(email: string): string {
    const sanitizedEmail = email.replace(/[^a-zA-Z0-9]/g, '-');
    return path.join(this.basePath, `${sanitizedEmail}.token.json`);
  }

  async save(email: string, token: TokenPayload): Promise<void> {
    await fs.mkdir(this.basePath, { recursive: true });
    await fs.writeFile(this.tokenPath(email), JSON.stringify(token, null, 2));
  }

  async load(email: string): Promise<TokenPayload | null> {
    try {
      const data = await fs.readFile(this.tokenPath(email), 'utf-8');
      return JSON.parse(data) as TokenPayload;
    } catch (err: any) {
      if (err && err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async delete(email: string): Promise<void> {
    try {
      await fs.unlink(this.tokenPath(email));
    } catch (err: any) {
      if (err && err.code !== 'ENOENT') throw err;
    }
  }
}
