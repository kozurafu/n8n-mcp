import { createHash } from 'crypto';
import { describe, expect, it } from 'vitest';
import { OAuthProvider } from '../../../src/oauth/oauth-provider';

function provider(fetchClientMetadata?: (url: string) => Promise<unknown>): OAuthProvider {
  return new OAuthProvider({
    issuer: 'https://n8n-mcp.example.com',
    resource: 'https://n8n-mcp.example.com/mcp',
    accessTokenTtl: 3600,
    refreshTokenTtl: 28800,
    stateFile: '',
    fetchClientMetadata,
  });
}

describe('OAuthProvider', () => {
  it('advertises OAuth 2.1 discovery, PKCE S256, DCR and CIMD', () => {
    const metadata = provider().authorizationServerMetadata();
    expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
    expect(metadata.token_endpoint_auth_methods_supported).toContain('none');
    expect(metadata.registration_endpoint).toBe('https://n8n-mcp.example.com/register');
    expect(metadata.client_id_metadata_document_supported).toBe(true);
  });

  it('completes a public-client authorization-code flow with PKCE', () => {
    const oauth = provider();
    const registration = oauth.registerClient({
      client_name: 'Test client',
      redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
      token_endpoint_auth_method: 'none',
    });
    const clientId = registration.client_id as string;
    const verifier = 'a'.repeat(64);
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const request = new URLSearchParams({
      client_id: clientId,
      redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: 'https://n8n-mcp.example.com/mcp',
    });
    const redirect = oauth.completeAuthorization(oauth.validateAuthorizationRequest(request)).redirectTo;
    const code = new URL(redirect).searchParams.get('code')!;
    const tokens = oauth.exchange(new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      code_verifier: verifier,
      resource: 'https://n8n-mcp.example.com/mcp',
    }));
    expect(tokens.token_type).toBe('Bearer');
    expect(oauth.isValidAccessToken(tokens.access_token as string)).toBe(true);
  });

  it('accepts ChatGPT transitional CIMD when plural methods include none', async () => {
    const clientId = 'https://chatgpt.com/.well-known/oauth-client/test';
    const oauth = provider(async () => ({
      client_id: clientId,
      client_name: 'ChatGPT',
      redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_methods_supported: ['private_key_jwt', 'none'],
    }));
    await oauth.resolveClient(clientId);
    const request = new URLSearchParams({
      client_id: clientId,
      redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      response_type: 'code',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
    });
    expect(oauth.validateAuthorizationRequest(request).client.token_endpoint_auth_method).toBe('none');
  });

  it('rejects PKCE plain', () => {
    const oauth = provider();
    const registration = oauth.registerClient({
      redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
    });
    expect(() => oauth.validateAuthorizationRequest(new URLSearchParams({
      client_id: registration.client_id as string,
      redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      response_type: 'code',
      code_challenge: 'plain-value',
      code_challenge_method: 'plain',
    }))).toThrow(/S256/);
  });
});
