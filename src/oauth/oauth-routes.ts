import express, { type Express, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { AuthManager } from '../utils/auth';
import {
  OAuthErrorResponse,
  OAuthProvider,
  isClientIdUrl,
} from './oauth-provider';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function authorizePage(params: URLSearchParams, clientName: string, error?: string): string {
  const hidden = [...params.entries()]
    .filter(([key]) => key !== 'mcp_auth_token')
    .map(([key, value]) =>
      `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`
    )
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ${escapeHtml(clientName)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 10vh auto; padding: 0 1rem; color: #171717; }
    h1 { font-size: 1.35rem; }
    p { line-height: 1.5; color: #444; }
    label { display: block; font-weight: 650; margin: 1.2rem 0 0.4rem; }
    input[type=password] { width: 100%; padding: .7rem; font-size: 1rem; border: 1px solid #aaa; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 1.2rem; width: 100%; padding: .75rem; font-size: 1rem; border: 0; border-radius: 6px; background: #6b16ed; color: white; cursor: pointer; }
    .error { background: #fde8e8; border: 1px solid #f5b5b5; border-radius: 6px; padding: .7rem; color: #8a1f1f; }
    .note { font-size: .86rem; color: #666; }
  </style>
</head>
<body>
  <h1>Authorize ${escapeHtml(clientName)}</h1>
  <p><strong>${escapeHtml(clientName)}</strong> wants to connect to your private n8n management MCP server.</p>
  ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  <form method="post" action="/authorize">
    ${hidden}
    <label for="mcp_auth_token">MCP authorization token</label>
    <input type="password" id="mcp_auth_token" name="mcp_auth_token" autocomplete="off" required>
    <p class="note">This is the MCP_AUTH_TOKEN stored privately in Coolify. It is used once to prove access and is never sent to ChatGPT or stored by the OAuth server.</p>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>`;
}

function sendOAuthError(res: Response, error: OAuthErrorResponse): void {
  res.status(error.status).json({ error: error.code, error_description: error.description });
}

function stringParams(values: Record<string, unknown>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (typeof value === 'string') params.append(key, value);
  }
  return params;
}

export interface OAuthRoutes {
  provider: OAuthProvider;
  resourceMetadataUrl: string;
}

export function registerOAuthRoutes(
  app: Express,
  publicUrl: string,
  proofToken: string,
): OAuthRoutes {
  const issuer = publicUrl.replace(/\/+$/, '');
  const resource = `${issuer}/mcp`;
  const provider = new OAuthProvider({
    issuer,
    resource,
    accessTokenTtl: Number(process.env.MCP_ACCESS_TOKEN_TTL || 3600),
    refreshTokenTtl: Number(process.env.MCP_REFRESH_TOKEN_TTL || 28800),
    stateFile: process.env.MCP_OAUTH_STATE_FILE || '/app/data/oauth-state.json',
  });

  const limiter = rateLimit({
    windowMs: 60_000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
  });
  const formParser = express.urlencoded({ extended: false, limit: '32kb' });
  const registrationParser = express.json({ limit: '16kb' });

  const resourceMetadataUrl = `${issuer}/.well-known/oauth-protected-resource/mcp`;

  app.get([
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
  ], (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(provider.protectedResourceMetadata());
  });

  app.get([
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-authorization-server/mcp',
  ], (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(provider.authorizationServerMetadata());
  });

  app.post('/register', limiter, registrationParser, (req, res) => {
    try {
      res.status(201).json(provider.registerClient(req.body as Record<string, unknown>));
    } catch (error) {
      if (error instanceof OAuthErrorResponse) return sendOAuthError(res, error);
      res.status(400).json({ error: 'invalid_client_metadata' });
    }
  });

  app.get('/authorize', limiter, async (req: Request, res: Response) => {
    const params = stringParams(req.query);
    try {
      const clientId = params.get('client_id') || '';
      if (isClientIdUrl(clientId)) await provider.resolveClient(clientId);
      const validated = provider.validateAuthorizationRequest(params);
      res.setHeader('Cache-Control', 'no-store');
      res.type('html').send(authorizePage(params, validated.client.client_name || 'An MCP client'));
    } catch (error) {
      const description = error instanceof OAuthErrorResponse ? error.description : 'invalid request';
      res.status(400).type('html').send(`<p>Authorization request rejected: ${escapeHtml(description)}</p>`);
    }
  });

  app.post('/authorize', limiter, formParser, async (req: Request, res: Response) => {
    const params = stringParams(req.body as Record<string, unknown>);
    let validated: ReturnType<OAuthProvider['validateAuthorizationRequest']>;
    try {
      const clientId = params.get('client_id') || '';
      if (isClientIdUrl(clientId)) await provider.resolveClient(clientId);
      validated = provider.validateAuthorizationRequest(params);
    } catch (error) {
      const description = error instanceof OAuthErrorResponse ? error.description : 'invalid request';
      res.status(400).type('html').send(`<p>Authorization request rejected: ${escapeHtml(description)}</p>`);
      return;
    }

    const presented = params.get('mcp_auth_token') || '';
    params.delete('mcp_auth_token');
    if (!presented || !AuthManager.timingSafeCompare(presented, proofToken)) {
      res.status(401).type('html').send(
        authorizePage(params, validated.client.client_name || 'An MCP client', 'That token was not accepted. Check it and try again.')
      );
      return;
    }

    const { redirectTo } = provider.completeAuthorization(validated);
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, redirectTo);
  });

  app.post('/token', limiter, formParser, async (req: Request, res: Response) => {
    const params = stringParams(req.body as Record<string, unknown>);
    try {
      await provider.resolveClient(params.get('client_id') || '');
      res.setHeader('Cache-Control', 'no-store');
      res.json(provider.exchange(params));
    } catch (error) {
      if (error instanceof OAuthErrorResponse) return sendOAuthError(res, error);
      res.status(400).json({ error: 'invalid_request' });
    }
  });

  return { provider, resourceMetadataUrl };
}
