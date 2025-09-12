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

