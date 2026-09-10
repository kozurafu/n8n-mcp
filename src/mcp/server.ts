import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { ToolDefinition } from '../types';
import type { McpToolResponse } from '../types/n8n-api';
import { existsSync, readFileSync, promises as fs } from 'fs';
import path from 'path';
import { n8nDocumentationToolsFinal } from './tools';
import { UIAppRegistry } from './ui';
import { SkillResourceRegistry } from './skills';
import { n8nManagementTools, TOOL_OPERATION_PARAM, DESTRUCTIVE_TOOL_OPERATIONS } from './tools-n8n-manager';
import {
  getDisabledTools as getDisabledToolsPolicy,
  getDisabledToolOperations as getDisabledToolOperationsPolicy,
  getValidOperations,
  isOperationDisabled,
  resolveRequestedOperation,
} from './tool-policy';
import { makeToolsN8nFriendly } from './tools-n8n-friendly';
import { getWorkflowExampleString } from './workflow-examples';
import { logger } from '../utils/logger';
import { hasText, resolveGetNodeAliases, suggestExecutionsAction, withWorkflowIdAlias } from './param-aliases';
import { installStdioGuard } from '../utils/stdio-guard';
import { summarizeToolCallArgs } from '../utils/redaction';
import { NodeRepository } from '../database/node-repository';
import { DatabaseAdapter, createDatabaseAdapter } from '../database/database-adapter';
import { getSharedDatabase, releaseSharedDatabase, SharedDatabaseState } from '../database/shared-database';
import { PropertyFilter } from '../services/property-filter';
import { TaskTemplates } from '../services/task-templates';
import { ConfigValidator } from '../services/config-validator';
import { EnhancedConfigValidator, ValidationMode, ValidationProfile } from '../services/enhanced-config-validator';
import { PropertyDependencies } from '../services/property-dependencies';
import { TypeStructureService } from '../services/type-structure-service';
import { SimpleCache } from '../utils/simple-cache';
import { TemplateService } from '../templates/template-service';
import { WorkflowValidator } from '../services/workflow-validator';
import { isN8nApiConfigured } from '../config/n8n-api';
import * as n8nHandlers from './handlers-n8n-manager';
import { handleManageAgents } from './handlers-agents';
import { handleExploreNodeResources, handleListCatalog } from './handlers-official-tools';
import { handleUpdatePartialWorkflow } from './handlers-workflow-diff';
import { getToolDocumentation, getToolsOverview } from './tools-documentation';
import { PROJECT_VERSION } from '../utils/version';
import { getNodeTypeAlternatives, getWorkflowNodeType } from '../utils/node-utils';
import { NodeTypeNormalizer } from '../utils/node-type-normalizer';
import { parseTypeVersion } from '../utils/typeversion';
import { ToolValidation, Validator, ValidationError } from '../utils/validation-schemas';
import {
  negotiateProtocolVersion,
  logProtocolNegotiation,
  STANDARD_PROTOCOL_VERSION
} from '../utils/protocol-version';
import { BreakingChangeDetector, VersionUpgradeAnalysis } from '../services/breaking-change-detector';
import { normalizeNodeVersion } from '../parsers/node-parser';
import { InstanceContext } from '../types/instance-context';
import type { AdditionalTool, AdditionalToolContext } from '../types/additional-tools';
import { telemetry } from '../telemetry';
import { EarlyErrorLogger } from '../telemetry/early-error-logger';
import { STARTUP_CHECKPOINTS } from '../telemetry/startup-checkpoints';

// Largest single inbound JSON-RPC message the stdio transport will buffer.
//
// @modelcontextprotocol/sdk 1.30.0 introduced a cap here where there was none,
// defaulting to 10 MB, and the failure mode is not a tool error the client can
// report — the transport emits an error and closes, so the session dies. stdio
// is a local pipe to the user's own MCP client rather than an untrusted network
// caller, so the case for a tight bound is weaker than on HTTP, while the cost
// of tripping it is higher: the session dies before any tool call can report
// what happened, and on the npx path the user's machine has the version cached,
// so a fix reaches them slowly. 64 MB keeps a backstop against a stream that
// never terminates a message, with room well above any workflow body the
// bundled template corpus suggests is realistic.
//
// The ceiling is not a memory ceiling. The SDK accumulates with
// Buffer.concat([existing, chunk]), so a message approaching the limit holds
// roughly twice its size while the buffers overlap, and the parsed object then
// coexists with the string it was parsed from. A container sized well below
// that should lower this rather than inherit it, which is what the env override
// is for — the default suits the desktop and npx case the limit was raised for.
const STDIO_MAX_BUFFER_SIZE = Math.max(
  1024 * 1024,
  parseInt(process.env.N8N_MCP_STDIO_MAX_BUFFER_SIZE || '', 10) || 64 * 1024 * 1024
);

/**
 * Escape a string for safe use as a literal inside `new RegExp(...)`.
 *
 * Addresses CodeQL js/regex-injection: search queries are user-controlled,
 * and passing them directly into `new RegExp` lets a crafted query either
 * alter matching semantics (e.g. `.*`) or trigger polynomial/exponential
 * backtracking. We only ever want literal substring matching with word
 * boundaries, so escaping all regex metacharacters is the right fix.
 */
function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

interface NodeRow {
  node_type: string;
  package_name: string;
  display_name: string;
  description?: string;
  category?: string;
  development_style?: string;
  is_ai_tool: number;
  is_trigger: number;
  is_webhook: number;
  is_versioned: number;
  is_tool_variant: number;
  tool_variant_of?: string;
  has_tool_variant: number;
  version?: string;
  documentation?: string;
  properties_schema?: string;
  operations?: string;
  credentials_required?: string;
  // AI documentation fields
  ai_documentation_summary?: string;
  ai_summary_generated_at?: string;
}

interface VersionSummary {
  currentVersion: string;
  totalVersions: number;
  hasVersionHistory: boolean;
}

interface ToolVariantGuidance {
  isToolVariant: boolean;
  toolVariantOf?: string;
  hasToolVariant: boolean;
  toolVariantNodeType?: string;
  guidance?: string;
}

interface NodeMinimalInfo {
  nodeType: string;
  workflowNodeType: string;
  displayName: string;
  description: string;
  category: string;
  package: string;
  isAITool: boolean;
  isTrigger: boolean;
  isWebhook: boolean;
  toolVariantInfo?: ToolVariantGuidance;
}

interface NodeStandardInfo {
  nodeType: string;
  displayName: string;
  description: string;
  category: string;
  requiredProperties: any[];
  commonProperties: any[];
  operations?: any[];
  credentials?: any;
  examples?: any[];
  versionInfo: VersionSummary;
  toolVariantInfo?: ToolVariantGuidance;
}

interface NodeFullInfo {
  nodeType: string;
  displayName: string;
  description: string;
  category: string;
  properties: any[];
  operations?: any[];
  credentials?: any;
  documentation?: string;
  versionInfo: VersionSummary;
  toolVariantInfo?: ToolVariantGuidance;
}

interface VersionHistoryInfo {
  nodeType: string;
  versions: any[];
  latestVersion: string;
  hasBreakingChanges: boolean;
}

interface VersionComparisonInfo {
  nodeType: string;
  fromVersion: string;
  toVersion: string;
  changes: any[];
  breakingChanges?: any[];
  migrations?: any[];
}

type NodeInfoResponse = NodeMinimalInfo | NodeStandardInfo | NodeFullInfo | VersionHistoryInfo | VersionComparisonInfo;

interface MCPServerOptions {
  additionalTools?: AdditionalTool[];
}

export class N8NDocumentationMCPServer {
  private server: Server;
  private db: DatabaseAdapter | null = null;
  private repository: NodeRepository | null = null;
  private breakingChangeDetector: BreakingChangeDetector | null = null;
  private templateService: TemplateService | null = null;
  private initialized: Promise<void>;
  private cache = new SimpleCache();
  private clientInfo: any = null;
  private instanceContext?: InstanceContext;
  private previousTool: string | null = null;
  private previousToolTimestamp: number = Date.now();
  private earlyLogger: EarlyErrorLogger | null = null;
  private disabledToolsCache: Set<string> | null = null;
  private disabledToolOperationsCache: Map<string, Set<string>> | null = null;
  private filteredToolDefinitionsCache: Map<string, any> | null = null;
  private useSharedDatabase: boolean = false;  // Track if using shared DB for cleanup
  private sharedDbState: SharedDatabaseState | null = null;  // Reference to shared DB state for release
  private isShutdown: boolean = false;  // Prevent double-shutdown
  private additionalToolsByName: Map<string, AdditionalTool> = new Map();

  constructor(instanceContext?: InstanceContext, earlyLogger?: EarlyErrorLogger, options?: MCPServerOptions) {
    // The constructor starts database initialization below without awaiting it,
    // and that logs — so by the time run() could install the guard, output has
    // already been written. Install here whenever an MCP mode is declared and it
    // is not http, which covers noncanonical values like 'STDIO' or a typo.
    //
    // Deliberately keyed on MCP_MODE being *set*: with no mode declared this is
    // an ordinary library embedding (or a CLI script), where filtering stdout
    // would be surprising. Those callers are still covered from run() onward,
    // and can call installStdioGuard() themselves before constructing — it is
    // exported from the package root for exactly that.
    if (process.env.MCP_MODE && process.env.MCP_MODE !== 'http') {
      installStdioGuard();
    }

    this.instanceContext = instanceContext;
    this.earlyLogger = earlyLogger || null;
    this.registerAdditionalTools(options?.additionalTools || []);
    // Check for test environment first
    const envDbPath = process.env.NODE_DB_PATH;
    let dbPath: string | null = null;
    
    let possiblePaths: string[] = [];
    
    if (envDbPath && (envDbPath === ':memory:' || existsSync(envDbPath))) {
      dbPath = envDbPath;
    } else {
      // Try multiple database paths
      possiblePaths = [
        path.join(process.cwd(), 'data', 'nodes.db'),
        path.join(__dirname, '../../data', 'nodes.db'),
        './data/nodes.db'
      ];
      
      for (const p of possiblePaths) {
        if (existsSync(p)) {
          dbPath = p;
          break;
        }
      }
    }
    
    if (!dbPath) {
      logger.error('Database not found in any of the expected locations:', possiblePaths);
      throw new Error('Database nodes.db not found. Please run npm run rebuild first.');
    }
    
    // Initialize database asynchronously
    this.initialized = this.initializeDatabase(dbPath).then(() => {
      // After database is ready, check n8n API configuration (v2.18.3)
      if (this.earlyLogger) {
        this.earlyLogger.logCheckpoint(STARTUP_CHECKPOINTS.N8N_API_CHECKING);
      }

      // Log n8n API configuration status at startup
      const apiConfigured = isN8nApiConfigured();
      const totalTools = apiConfigured ?
        n8nDocumentationToolsFinal.length + n8nManagementTools.length :
        n8nDocumentationToolsFinal.length;

      logger.info(`MCP server initialized with ${totalTools} tools (n8n API: ${apiConfigured ? 'configured' : 'not configured'})`);

      if (this.earlyLogger) {
        this.earlyLogger.logCheckpoint(STARTUP_CHECKPOINTS.N8N_API_READY);
      }
    });

    // Attach a no-op catch handler to prevent Node.js from flagging this as an
    // unhandled rejection in the interval between construction and the first
    // await of this.initialized (via ensureInitialized). This does NOT suppress
    // the error: the original this.initialized promise still rejects, and
    // ensureInitialized() will re-throw it when awaited.
    this.initialized.catch(() => {});

    logger.info('Initializing n8n Documentation MCP server');
    
    this.server = new Server(
      {
        name: 'n8n-documentation-mcp',
        version: PROJECT_VERSION,
        icons: [
          {
            src: "https://www.n8n-mcp.com/logo.png",
            mimeType: "image/png",
            sizes: ["192x192"]
          },
          {
            src: "https://www.n8n-mcp.com/logo-128.png",
            mimeType: "image/png",
            sizes: ["128x128"]
          },
          {
            src: "https://www.n8n-mcp.com/logo-48.png",
            mimeType: "image/png",
            sizes: ["48x48"]
          }
        ],
        websiteUrl: "https://n8n-mcp.com"
      },
      {
        capabilities: {
          tools: {},
          resources: {},
        },
      }
    );

    UIAppRegistry.load();
    SkillResourceRegistry.load();
    this.setupHandlers();
  }

  private registerAdditionalTools(additionalTools: AdditionalTool[]): void {
    const builtInToolNames = new Set([
      ...n8nDocumentationToolsFinal.map(tool => tool.name),
      ...n8nManagementTools.map(tool => tool.name),
    ]);

    for (const additionalTool of additionalTools) {
      const toolName = additionalTool.tool.name;
      if (builtInToolNames.has(toolName)) {
        throw new Error(`Additional tool "${toolName}" collides with a built-in tool`);
      }

      if (this.additionalToolsByName.has(toolName)) {
        throw new Error(`Duplicate additional tool "${toolName}" provided`);
      }

      // Defensive deep copy of the tool definition so per-session servers that
      // share the same engine-level additionalTools array cannot mutate each
      // other's tool descriptors (cross-tenant isolation).
      this.additionalToolsByName.set(toolName, {
        tool: structuredClone(additionalTool.tool),
        handler: additionalTool.handler,
      });
    }
  }

  private getEnabledAdditionalTools(disabledTools: Set<string>): Tool[] {
    return Array.from(this.additionalToolsByName.values())
      .map(toolDef => toolDef.tool)
      .filter(tool => !disabledTools.has(tool.name));
  }

  /**
   * Look up a tool's schema by name across built-in and host-provided tools.
   * Used by the arg preprocessing pipeline so additional tools receive the
   * same client-bug coercion and schema validation as built-ins.
   */
  private findToolSchema(name: string): { name: string; inputSchema?: any } | undefined {
    return n8nDocumentationToolsFinal.find(t => t.name === name)
      ?? n8nManagementTools.find(t => t.name === name)
      ?? this.additionalToolsByName.get(name)?.tool;
  }

  /**
   * Close the server and release resources.
   * Should be called when the session is being removed.
   *
   * Order of cleanup:
   * 1. Close MCP server connection
   * 2. Destroy cache (clears entries AND stops cleanup timer)
   * 3. Release shared database OR close dedicated connection
   * 4. Null out references to help GC
   *
   * IMPORTANT: For shared databases, we only release the reference (decrement refCount),
   * NOT close the database. The database stays open for other sessions.
   * For in-memory databases (tests), we close the dedicated connection.
   */
  async close(): Promise<void> {
    // Wait for initialization to complete (or fail) before cleanup
    // This prevents race conditions where close runs while init is in progress
    try {
      await this.initialized;
    } catch (error) {
      // Initialization failed - that's OK, we still need to clean up
      logger.debug('Initialization had failed, proceeding with cleanup', {
        error: error instanceof Error ? error.message : String(error)
      });
    }

    try {
      await this.server.close();

      // Use destroy() not clear() - also stops the cleanup timer
      this.cache.destroy();

      // Handle database cleanup based on whether it's shared or dedicated
      if (this.useSharedDatabase && this.sharedDbState) {
        // Shared database: release reference, don't close
        // The database stays open for other sessions
        releaseSharedDatabase(this.sharedDbState);
        logger.debug('Released shared database reference');
      } else if (this.db) {
        // Dedicated database (in-memory for tests): close it
        try {
          this.db.close();
        } catch (dbError) {
          logger.warn('Error closing database', {
            error: dbError instanceof Error ? dbError.message : String(dbError)
          });
        }
      }

      // Null out references to help garbage collection
      this.db = null;
      this.repository = null;
      this.templateService = null;
      this.earlyLogger = null;
      this.sharedDbState = null;
    } catch (error) {
      // Log but don't throw - cleanup should be best-effort
      logger.warn('Error closing MCP server', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async initializeDatabase(dbPath: string): Promise<void> {
    try {
      // Checkpoint: Database connecting (v2.18.3)
      if (this.earlyLogger) {
        this.earlyLogger.logCheckpoint(STARTUP_CHECKPOINTS.DATABASE_CONNECTING);
      }

      logger.debug('Database initialization starting...', { dbPath });

      // For in-memory databases (tests), create a dedicated connection
      // For regular databases, use the shared connection to prevent memory leaks
      if (dbPath === ':memory:') {
        this.db = await createDatabaseAdapter(dbPath);
        logger.debug('Database adapter created (in-memory mode)');
        // In-memory schema already includes workflow_versions.instance_id, so no
        // migration is needed; and being ephemeral, the age-retention sweep that
        // initializeSharedDatabase() runs would have nothing to prune here.
        await this.initializeInMemorySchema();
        logger.debug('In-memory schema initialized');
        this.repository = new NodeRepository(this.db);
        this.templateService = new TemplateService(this.db);
        // Initialize similarity services for enhanced validation
        EnhancedConfigValidator.initializeSimilarityServices(this.repository);
        this.useSharedDatabase = false;
      } else {
        // Use shared database connection to prevent ~900MB memory leak per session
        // See: Memory leak fix - database was being duplicated per session
        const sharedState = await getSharedDatabase(dbPath);
        this.db = sharedState.db;
        this.repository = sharedState.repository;
        this.templateService = sharedState.templateService;
        this.sharedDbState = sharedState;
        this.useSharedDatabase = true;
        logger.debug('Using shared database connection');
      }

      logger.debug('Node repository initialized');
      logger.debug('Template service initialized');
      logger.debug('Similarity services initialized');

      // Checkpoint: Database connected (v2.18.3)
      if (this.earlyLogger) {
        this.earlyLogger.logCheckpoint(STARTUP_CHECKPOINTS.DATABASE_CONNECTED);
      }

      logger.info(`Database initialized successfully from: ${dbPath}`);
    } catch (error) {
      logger.error('Failed to initialize database:', error);
      throw new Error(`Failed to open database: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  private async initializeInMemorySchema(): Promise<void> {
    if (!this.db) return;

    // Read and execute schema
    const schemaPath = path.join(__dirname, '../../src/database/schema.sql');
    const schema = await fs.readFile(schemaPath, 'utf-8');

    // Parse SQL statements properly (handles BEGIN...END blocks in triggers)
    const statements = this.parseSQLStatements(schema);

    for (const statement of statements) {
      if (statement.trim()) {
        try {
          this.db.exec(statement);
        } catch (error) {
          logger.error(`Failed to execute SQL statement: ${statement.substring(0, 100)}...`, error);
          throw error;
        }
      }
    }
  }

  /**
   * Parse SQL statements from schema file, properly handling multi-line statements
   * including triggers with BEGIN...END blocks
   */
  private parseSQLStatements(sql: string): string[] {
    const statements: string[] = [];
    let current = '';
    let inBlock = false;

    const lines = sql.split('\n');

    for (const line of lines) {
      const trimmed = line.trim().toUpperCase();

      // Skip comments and empty lines
      if (trimmed.startsWith('--') || trimmed === '') {
        continue;
      }

      // Track BEGIN...END blocks (triggers, procedures)
      if (trimmed.includes('BEGIN')) {
        inBlock = true;
      }

      current += line + '\n';

      // End of block (trigger/procedure)
      if (inBlock && trimmed === 'END;') {
        statements.push(current.trim());
        current = '';
        inBlock = false;
        continue;
      }

      // Regular statement end (not in block)
      if (!inBlock && trimmed.endsWith(';')) {
        statements.push(current.trim());
        current = '';
      }
    }

    // Add any remaining content
    if (current.trim()) {
      statements.push(current.trim());
    }

    return statements.filter(s => s.length > 0);
  }
  
  private async ensureInitialized(): Promise<void> {
    await this.initialized;
    if (!this.db || !this.repository) {
      throw new Error('Database not initialized');
    }

    // Validate database health on first access
    if (!this.dbHealthChecked) {
      await this.validateDatabaseHealth();
      this.dbHealthChecked = true;
    }
  }

  private dbHealthChecked: boolean = false;

  private async validateDatabaseHealth(): Promise<void> {
    if (!this.db) return;

    try {
      // Check if nodes table has data
      const nodeCount = this.db.prepare('SELECT COUNT(*) as count FROM nodes').get() as { count: number };

      if (nodeCount.count === 0) {
        logger.error('CRITICAL: Database is empty - no nodes found! Please run: npm run rebuild');
        throw new Error('Database is empty. Run "npm run rebuild" to populate node data.');
      }

      // Check if FTS5 table exists (wrap in try-catch for sql.js compatibility)
      try {
        const ftsExists = this.db.prepare(`
          SELECT name FROM sqlite_master
          WHERE type='table' AND name='nodes_fts'
        `).get();

        if (!ftsExists) {
          logger.warn('FTS5 table missing - search performance will be degraded. Please run: npm run rebuild');
        } else {
          const ftsCount = this.db.prepare('SELECT COUNT(*) as count FROM nodes_fts').get() as { count: number };
          if (ftsCount.count === 0) {
            logger.warn('FTS5 index is empty - search will not work properly. Please run: npm run rebuild');
          }
        }
      } catch (ftsError) {
        // FTS5 not supported (e.g., sql.js fallback) - this is OK, just warn
        logger.warn('FTS5 not available - using fallback search. For better performance, ensure better-sqlite3 is properly installed.');
      }

      logger.info(`Database health check passed: ${nodeCount.count} nodes loaded`);
    } catch (error) {
      logger.error('Database health check failed:', error);
      throw error;
    }
  }

  /**
   * Per-instance cache over the shared `DISABLED_TOOLS` policy
   * (src/mcp/tool-policy.ts), which does the parsing, the safety limits and
   * the operator-facing logging.
   *
   * @returns Set of disabled tool names
   */
  private getDisabledTools(): Set<string> {
    if (this.disabledToolsCache !== null) {
      return this.disabledToolsCache;
    }
    this.disabledToolsCache = getDisabledToolsPolicy();
    return this.disabledToolsCache;
  }

  /**
   * Per-instance cache over the shared `DISABLED_TOOL_OPERATIONS` policy
   * (src/mcp/tool-policy.ts). Also pre-builds filteredToolDefinitionsCache so
   * ListTools requests pay no per-request cloning cost.
   *
   * @returns Map of toolName -> Set of disabled operation names
   */
  private getDisabledToolOperations(): Map<string, Set<string>> {
    if (this.disabledToolOperationsCache !== null) {
      return this.disabledToolOperationsCache;
    }

    const result = getDisabledToolOperationsPolicy();
    this.disabledToolOperationsCache = result;
    this.filteredToolDefinitionsCache = this.buildFilteredToolDefinitions(result);
    return result;
  }

  /**
   * Builds deep-cloned, operation-filtered tool definitions for every tool that
   * has disabled operations. Called once on the first getDisabledToolOperations()
   * invocation and cached — subsequent ListTools requests pay no cloning cost.
   */
  private buildFilteredToolDefinitions(disabledOps: Map<string, Set<string>>): Map<string, any> {
    const cache = new Map<string, any>();

    for (const [toolName, ops] of disabledOps) {
      const paramName = TOOL_OPERATION_PARAM[toolName];
      if (!paramName) continue;

      const original = n8nManagementTools.find(t => t.name === toolName);
      if (!original) continue;

      const cloned = JSON.parse(JSON.stringify(original));

      // Operations still reachable after filtering, counted over the schema enum
      // UNION the destructive set so virtual operations (destructive values that
      // are not selectable enum values, e.g. `expose`) are not overlooked. Used
      // only for the read-only annotation recompute below — a virtual operation
      // is a write path that survives, but it is never something a caller can
      // select, so it must not keep the "nothing left to call" warning quiet.
      const remaining = [...getValidOperations(toolName)].filter(v => !ops.has(v));

      const param = cloned.inputSchema?.properties?.[paramName];
      let defaultRemoved = false;
      if (param?.enum) {
        param.enum = (param.enum as string[]).filter(v => !ops.has(v.toLowerCase()));
        if (typeof param.default === 'string' && ops.has(param.default.toLowerCase())) {
          delete param.default;
          defaultRemoved = true;
        }
        if (param.enum.length === 0) {
          logger.warn(
            `DISABLED_TOOL_OPERATIONS: all operations for '${toolName}' are disabled ` +
            `but the tool still appears in ListTools. ` +
            `Consider adding '${toolName}' to DISABLED_TOOLS instead.`
          );
        }
        if (param.description) {
          const disabledList = [...ops].join(', ');
          param.description = `${param.description} (disabled by server policy: ${disabledList}`
            + `${defaultRemoved ? '; no default, pass a value' : ''})`;
        }
      }

      const disabledList = [...ops].join(', ');
      cloned.description = `${cloned.description}\n\n> Operations disabled by server policy: ${disabledList}`
        + (defaultRemoved ? `. The default for ${paramName} was one of them, so ${paramName} must be passed explicitly.` : '');

      // If filtering removed every destructive operation, the tool is now
      // read-only — recompute its MCP annotations so hosts that honor them
      // (e.g. to gate/hide destructive tools) don't keep restricting the
      // remaining read paths, which would defeat the read-only deployment use case.
      const destructive = DESTRUCTIVE_TOOL_OPERATIONS[toolName];
      if (destructive && cloned.annotations) {
        const stillDestructive = remaining.some(v => destructive.has(String(v).toLowerCase()));
        if (!stillDestructive) {
          cloned.annotations = { ...cloned.annotations, readOnlyHint: true, destructiveHint: false };
        }
      }

      cache.set(toolName, cloned);
    }

    return cache;
  }

  private setupHandlers(): void {
    // Handle initialization
    this.server.setRequestHandler(InitializeRequestSchema, async (request) => {
      const clientVersion = request.params.protocolVersion;
      const clientCapabilities = request.params.capabilities;
      const clientInfo = request.params.clientInfo;
      
      logger.info('MCP Initialize request received', {
        clientVersion,
        clientCapabilities,
        clientInfo
      });

      // Track session start
      telemetry.trackSessionStart();

      // Store client info for later use
      this.clientInfo = clientInfo;
      
      // Negotiate protocol version based on client information
      const negotiationResult = negotiateProtocolVersion(
        clientVersion,
        clientInfo,
        undefined, // no user agent in MCP protocol
        undefined  // no headers in MCP protocol
      );
      
      logProtocolNegotiation(negotiationResult, logger, 'MCP_INITIALIZE');
      
      // Warn if there's a version mismatch (for debugging)
      if (clientVersion && clientVersion !== negotiationResult.version) {
        logger.warn(`Protocol version negotiated: client requested ${clientVersion}, server will use ${negotiationResult.version}`, {
          reasoning: negotiationResult.reasoning
        });
      }
      
      const response = {
        protocolVersion: negotiationResult.version,
        capabilities: {
          tools: {},
          resources: {},
        },
        serverInfo: {
          name: 'n8n-documentation-mcp',
          version: PROJECT_VERSION,
        },
      };
      
      logger.info('MCP Initialize response', { response });
      return response;
    });

    // Handle tool listing
    this.server.setRequestHandler(ListToolsRequestSchema, async (request) => {
      // Get disabled tools from environment variable
      const disabledTools = this.getDisabledTools();

      // Filter documentation tools based on disabled list
      const enabledDocTools = n8nDocumentationToolsFinal.filter(
        tool => !disabledTools.has(tool.name)
      );

      // Combine documentation tools with management tools if API is configured
      let tools = [...enabledDocTools];

      // Check if n8n API tools should be available
      // 1. Environment variables (backward compatibility)
      // 2. Instance context (multi-tenant support)
      // 3. Multi-tenant mode enabled (always show tools, runtime checks will handle auth)
      const hasEnvConfig = isN8nApiConfigured();
      const hasInstanceConfig = !!(this.instanceContext?.n8nApiUrl && this.instanceContext?.n8nApiKey);
      const isMultiTenantEnabled = process.env.ENABLE_MULTI_TENANT === 'true';

      const shouldIncludeManagementTools = hasEnvConfig || hasInstanceConfig || isMultiTenantEnabled;

      if (shouldIncludeManagementTools) {
        // Filter management tools based on disabled list
        const enabledMgmtTools = n8nManagementTools.filter(
          tool => !disabledTools.has(tool.name)
        );
        tools.push(...enabledMgmtTools);
        logger.debug(`Tool listing: ${tools.length} tools available (${enabledDocTools.length} documentation + ${enabledMgmtTools.length} management)`, {
          hasEnvConfig,
          hasInstanceConfig,
          isMultiTenantEnabled,
          disabledToolsCount: disabledTools.size
        });
      } else {
        logger.debug(`Tool listing: ${tools.length} tools available (documentation only)`, {
          hasEnvConfig,
          hasInstanceConfig,
          isMultiTenantEnabled,
          disabledToolsCount: disabledTools.size
        });
      }

      // Cast: MCP `Tool.description` is optional, `ToolDefinition.description` is required.
      tools.push(...(this.getEnabledAdditionalTools(disabledTools) as unknown as ToolDefinition[]));

      // Log filtered tools count if any tools are disabled
      if (disabledTools.size > 0) {
        const totalAvailableTools = n8nDocumentationToolsFinal.length +
          (shouldIncludeManagementTools ? n8nManagementTools.length : 0) +
          this.additionalToolsByName.size;
        logger.debug(`Filtered ${disabledTools.size} disabled tools, ${tools.length}/${totalAvailableTools} tools available`);
      }
      
      // Check if client is n8n (from initialization)
      const clientInfo = this.clientInfo;
      const isN8nClient = clientInfo?.name?.includes('n8n') || 
                         clientInfo?.name?.includes('langchain');
      
      if (isN8nClient) {
        logger.info('Detected n8n client, using n8n-friendly tool descriptions');
        tools = makeToolsN8nFriendly(tools);
      }
      
      // Log validation tools' input schemas for debugging
      const validationTools = tools.filter(t => t.name.startsWith('validate_'));
      validationTools.forEach(tool => {
        logger.info('Validation tool schema', {
          toolName: tool.name,
          inputSchema: JSON.stringify(tool.inputSchema, null, 2),
          hasOutputSchema: !!tool.outputSchema,
          description: tool.description
        });
      });
      
      // Apply per-operation filtered definitions (lazily built on first call, cached for all subsequent calls)
      const disabledToolOps = this.getDisabledToolOperations();
      if (disabledToolOps.size > 0 && this.filteredToolDefinitionsCache) {
        tools = tools.map(tool => this.filteredToolDefinitionsCache!.get(tool.name) ?? tool);
      }

      UIAppRegistry.injectToolMeta(tools);
      return { tools };
    });

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name: requestedName, arguments: args } = request.params;

      // ChatGPT custom connectors may send the connector-qualified tool name
      // back to the MCP server (for example, "n8n_mcp.n8n_health_check")
      // even though tools/list advertised the unqualified name. Accept only
      // our known connector prefix and keep all other names unchanged so the
      // normal unknown-tool validation still applies.
      const name = requestedName.startsWith('n8n_mcp.')
        ? requestedName.slice('n8n_mcp.'.length)
        : requestedName;
      
      // SECURITY (GHSA-wg4g-395p-mqv3): log metadata only, not raw arg values.
      logger.info('Tool call received', {
        toolName: name,
        ...(name !== requestedName ? { requestedToolName: requestedName } : {}),
        ...summarizeToolCallArgs(args),
        hasNodeType: !!(args && typeof args === 'object' && 'nodeType' in args),
        hasConfig: !!(args && typeof args === 'object' && 'config' in args),
      });

      // Check if tool is disabled via DISABLED_TOOLS environment variable
      const disabledTools = this.getDisabledTools();
      if (disabledTools.has(name)) {
        logger.warn(`Attempted to call disabled tool: ${name}`);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'TOOL_DISABLED',
              message: `Tool '${name}' is not available in this deployment. It has been disabled via DISABLED_TOOLS environment variable.`,
              tool: name
            }, null, 2)
          }],
          isError: true
        };
      }

      // Safeguard: if the entire args object arrives as a JSON string, parse it.
      // Some MCP clients may serialize the arguments object itself.
      let processedArgs: Record<string, any> | undefined = args;
      if (typeof args === 'string') {
        try {
          const parsed = JSON.parse(args as unknown as string);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            processedArgs = parsed;
            logger.warn(`Coerced stringified args object for tool "${name}"`);
          }
        } catch {
          logger.warn(`Tool "${name}" received string args that are not valid JSON`);
        }
      }

      // Workaround for n8n's nested output bug
      // Check if args contains nested 'output' structure from n8n's memory corruption
      if (args && typeof args === 'object' && 'output' in args) {
        try {
          const possibleNestedData = args.output;
          // If output is a string that looks like JSON, try to parse it
          if (typeof possibleNestedData === 'string' && possibleNestedData.trim().startsWith('{')) {
            const parsed = JSON.parse(possibleNestedData);
            if (parsed && typeof parsed === 'object') {
              // SECURITY (GHSA-wg4g-395p-mqv3): log key shape only, not values.
              logger.warn('Detected n8n nested output bug, attempting to extract actual arguments', {
                toolName: name,
                originalArgsKeys: Object.keys(args),
                extractedArgsKeys: Object.keys(parsed),
              });

              // Validate the extracted arguments match expected tool schema
              if (this.validateExtractedArgs(name, parsed)) {
                // Use the extracted data as args
                processedArgs = parsed;
              } else {
                logger.warn('Extracted arguments failed validation, using original args', {
                  toolName: name,
                  extractedArgsKeys: Object.keys(parsed),
                });
              }
            }
          }
        } catch (parseError) {
          logger.debug('Failed to parse nested output, continuing with original args', { 
            error: parseError instanceof Error ? parseError.message : String(parseError) 
          });
        }
      }

      // Workaround for Claude Desktop / Claude.ai MCP client bugs that
      // serialize parameters with wrong types. Coerces ALL mismatched types
      // (string↔object, string↔number, string↔boolean, etc.) using the
      // tool's inputSchema as the source of truth.
      processedArgs = this.coerceStringifiedJsonParams(name, processedArgs);

      // Strip undefined values from args (#611) — VS Code extension sends
      // explicit undefined values which Zod's .optional() rejects.
      // Removing them makes Zod treat them as missing (which .optional() allows).
      if (processedArgs) {
        processedArgs = JSON.parse(JSON.stringify(processedArgs));
      }

      // Check if the requested operation is disabled via DISABLED_TOOL_OPERATIONS.
      // Runs after argument normalization so clients that send args as a JSON string
      // are handled correctly regardless of serialization quirks.
      const disabledToolOps = this.getDisabledToolOperations();
      const disabledOpsForTool = disabledToolOps.get(name);
      if (disabledOpsForTool && disabledOpsForTool.size > 0) {
        const paramName = TOOL_OPERATION_PARAM[name];
        if (paramName) {
          // An omitted OR blank operation is checked as the tool's default
          // (this check runs before Zod applies it), so a rule naming that
          // default holds for both shapes.
          const requestedOp = resolveRequestedOperation(name, processedArgs);
          if (requestedOp && disabledOpsForTool.has(String(requestedOp).toLowerCase())) {
            logger.warn(`Attempted to call disabled operation: ${name}.${requestedOp}`);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  error: 'OPERATION_DISABLED',
                  message: `Operation '${requestedOp}' on tool '${name}' is disabled by server policy.`,
                  tool: name,
                  operation: requestedOp,
                  disabledOperations: [...disabledOpsForTool]
                }, null, 2)
              }],
              isError: true
            };
          }
        }
      }

      const isAdditionalTool = this.additionalToolsByName.has(name);

      try {
        // SECURITY (GHSA-wg4g-395p-mqv3): log metadata only, not raw arg values.
        logger.debug(`Executing tool: ${name}`, summarizeToolCallArgs(processedArgs));
        const startTime = Date.now();
        const result = await this.executeTool(name, processedArgs);
        const duration = Date.now() - startTime;
        logger.debug(`Tool ${name} executed successfully`);

        // Track tool usage and sequence
        telemetry.trackToolUsage(name, true, duration);

        // Track tool sequence if there was a previous tool
        if (this.previousTool) {
          const timeDelta = Date.now() - this.previousToolTimestamp;
          telemetry.trackToolSequence(this.previousTool, name, timeDelta);
        }

        // Update previous tool tracking
        this.previousTool = name;
        this.previousToolTimestamp = Date.now();

        if (isAdditionalTool) {
          // Host controls the response shape.
          return result;
        }
        
        // Ensure the result is properly formatted for MCP
        let responseText: string;
        let structuredContent: any = null;
        
        try {
          // For validation tools, check if we should use structured content
          if (name.startsWith('validate_') && typeof result === 'object' && result !== null) {
            // Clean up the result to ensure it matches the outputSchema
            const cleanResult = this.sanitizeValidationResult(result, name);
            structuredContent = cleanResult;
            responseText = JSON.stringify(cleanResult, null, 2);
          } else {
            responseText = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
          }
        } catch (jsonError) {
          logger.warn(`Failed to stringify tool result for ${name}:`, jsonError);
          responseText = String(result);
        }
        
        // Validate response size (n8n might have limits)
        if (responseText.length > 1000000) { // 1MB limit
          logger.warn(`Tool ${name} response is very large (${responseText.length} chars), truncating`);
          responseText = responseText.substring(0, 999000) + '\n\n[Response truncated due to size limits]';
          structuredContent = null; // Don't use structured content for truncated responses
        }
        
        // Build MCP response with strict schema compliance
        const mcpResponse: any = {
          content: [
            {
              type: 'text' as const,
              text: responseText,
            },
          ],
        };
        
        // For tools with outputSchema, structuredContent is REQUIRED by MCP spec
        if (name.startsWith('validate_') && structuredContent !== null) {
          mcpResponse.structuredContent = structuredContent;
        }

        return mcpResponse;
      } catch (error) {
        logger.error(`Error executing tool ${name}`, error);
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';

        // Track tool error
        telemetry.trackToolUsage(name, false);
        telemetry.trackError(
          error instanceof Error ? error.constructor.name : 'UnknownError',
          `tool_execution`,
          name,
          errorMessage
        );

        // Track tool sequence even for errors
        if (this.previousTool) {
          const timeDelta = Date.now() - this.previousToolTimestamp;
          telemetry.trackToolSequence(this.previousTool, name, timeDelta);
        }

        // Update previous tool tracking (even for failed tools)
        this.previousTool = name;
        this.previousToolTimestamp = Date.now();

        if (isAdditionalTool) {
          // Host controls error response shape. Skip the n8n-specific guidance
          // and arg-type diagnostic the built-in branch appends — those leak
          // n8n vocabulary into host tool surfaces. Handlers that want a
          // structured error response should return one instead of throwing.
          return {
            content: [
              {
                type: 'text',
                text: `Error executing tool ${name}: ${errorMessage}`,
              },
            ],
            isError: true,
          };
        }

        // Provide more helpful error messages for common n8n issues
        let helpfulMessage = `Error executing tool ${name}: ${errorMessage}`;

        if (errorMessage.includes('required') || errorMessage.includes('missing')) {
          helpfulMessage += '\n\nNote: This error often occurs when the AI agent sends incomplete or incorrectly formatted parameters. Please ensure all required fields are provided with the correct types.';
        } else if (errorMessage.includes('type') || errorMessage.includes('expected')) {
          helpfulMessage += '\n\nNote: This error indicates a type mismatch. The AI agent may be sending data in the wrong format (e.g., string instead of object).';
        } else if (errorMessage.includes('Unknown category') || errorMessage.includes('not found')) {
          helpfulMessage += '\n\nNote: The requested resource or category was not found. Please check the available options.';
        }

        // For n8n schema errors, add specific guidance
        if (name.startsWith('validate_') && (errorMessage.includes('config') || errorMessage.includes('nodeType'))) {
          helpfulMessage += '\n\nFor validation tools:\n- nodeType should be a string (e.g., "nodes-base.webhook")\n- config should be an object (e.g., {})';
        }

        // Include diagnostic info about received args to help debug client issues
        try {
          const argDiag = processedArgs && typeof processedArgs === 'object'
            ? Object.entries(processedArgs).map(([k, v]) => `${k}: ${typeof v}`).join(', ')
            : `args type: ${typeof processedArgs}`;
          helpfulMessage += `\n\n[Diagnostic] Received arg types: {${argDiag}}`;
        } catch { /* ignore diagnostic errors */ }

        return {
          content: [
            {
              type: 'text',
              text: helpfulMessage,
            },
          ],
          isError: true,
        };
      }
    });

    // Handle ListResources: UI apps + skill markdown
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      const apps = UIAppRegistry.getAllApps();
      const skills = SkillResourceRegistry.getAll();
      return {
        resources: [
          ...apps
            .filter(app => app.html !== null)
            .map(app => ({
              uri: app.config.uri,
              name: app.config.displayName,
              description: app.config.description,
              mimeType: app.config.mimeType,
            })),
          ...skills.map(skill => ({
            uri: skill.uri,
            name: skill.name,
            description: skill.description,
            mimeType: skill.mimeType,
          })),
        ],
      };
    });

    // Advertise URI templates so capable clients can construct skill URIs
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
      resourceTemplates: SkillResourceRegistry.getTemplates(),
    }));

    // Handle ReadResource for UI apps and skill markdown
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params.uri;

      const uiMatch = uri.match(/^ui:\/\/n8n-mcp\/(.+)$/);
      if (uiMatch) {
        const app = UIAppRegistry.getAppById(uiMatch[1]);
        if (!app || !app.html) {
          throw new Error(`UI app not found or not built: ${uiMatch[1]}`);
        }
        return {
          contents: [
            { uri: app.config.uri, mimeType: app.config.mimeType, text: app.html },
          ],
        };
      }

      if (uri.startsWith('skill://n8n-mcp/')) {
        const skill = SkillResourceRegistry.getByUri(uri);
        if (!skill) {
          throw new Error(`Skill resource not found: ${uri}`);
        }
        return {
          contents: [
            { uri: skill.uri, mimeType: skill.mimeType, text: skill.content },
          ],
        };
      }

      throw new Error(`Unknown resource URI: ${uri}`);
    });
  }

  /**
   * Sanitize validation result to match outputSchema
   */
  private sanitizeValidationResult(result: any, toolName: string): any {
    if (!result || typeof result !== 'object') {
      return result;
    }

    const sanitized = { ...result };

    // Ensure required fields exist with proper types and filter to schema-defined fields only
    if (toolName === 'validate_node_minimal') {
      // Filter to only schema-defined fields
      const filtered = {
        nodeType: String(sanitized.nodeType || ''),
        displayName: String(sanitized.displayName || ''),
        valid: Boolean(sanitized.valid),
        missingRequiredFields: Array.isArray(sanitized.missingRequiredFields) 
          ? sanitized.missingRequiredFields.map(String) 
          : []
      };
      return filtered;
    } else if (toolName === 'validate_node_operation') {
      // Ensure summary exists
      let summary = sanitized.summary;
      if (!summary || typeof summary !== 'object') {
        summary = {
          hasErrors: Array.isArray(sanitized.errors) ? sanitized.errors.length > 0 : false,
          errorCount: Array.isArray(sanitized.errors) ? sanitized.errors.length : 0,
          warningCount: Array.isArray(sanitized.warnings) ? sanitized.warnings.length : 0,
          suggestionCount: Array.isArray(sanitized.suggestions) ? sanitized.suggestions.length : 0
        };
      }
      
      // Filter to only schema-defined fields
      const filtered = {
        nodeType: String(sanitized.nodeType || ''),
        workflowNodeType: String(sanitized.workflowNodeType || sanitized.nodeType || ''),
        displayName: String(sanitized.displayName || ''),
        valid: Boolean(sanitized.valid),
        errors: Array.isArray(sanitized.errors) ? sanitized.errors : [],
        warnings: Array.isArray(sanitized.warnings) ? sanitized.warnings : [],
        suggestions: Array.isArray(sanitized.suggestions) ? sanitized.suggestions : [],
        summary: summary
      };
      return filtered;
    } else if (toolName.startsWith('validate_workflow')) {
      sanitized.valid = Boolean(sanitized.valid);
      
      // Ensure arrays exist
      sanitized.errors = Array.isArray(sanitized.errors) ? sanitized.errors : [];
      sanitized.warnings = Array.isArray(sanitized.warnings) ? sanitized.warnings : [];
      
      // Ensure statistics/summary exists
      if (toolName === 'validate_workflow') {
        if (!sanitized.summary || typeof sanitized.summary !== 'object') {
          sanitized.summary = {
            totalNodes: 0,
            enabledNodes: 0,
            triggerNodes: 0,
            validConnections: 0,
            invalidConnections: 0,
            expressionsValidated: 0,
            errorCount: sanitized.errors.length,
            warningCount: sanitized.warnings.length
          };
        }
      } else {
        if (!sanitized.statistics || typeof sanitized.statistics !== 'object') {
          sanitized.statistics = {
            totalNodes: 0,
            triggerNodes: 0,
            validConnections: 0,
            invalidConnections: 0,
            expressionsValidated: 0
          };
        }
      }
    }

    // Remove undefined values to ensure clean JSON
    return JSON.parse(JSON.stringify(sanitized));
  }

  /**
   * Enhanced parameter validation using schemas
   */
  private validateToolParams(toolName: string, args: any, legacyRequiredParams?: string[]): void {
    try {
      // If legacy required params are provided, use the new validation but fall back to basic if needed
      let validationResult;
      
      switch (toolName) {
        case 'validate_node':
          // Consolidated tool handles both modes - validate as operation for now
          validationResult = ToolValidation.validateNodeOperation(args);
          break;
        case 'validate_workflow':
          validationResult = ToolValidation.validateWorkflow(args);
          break;
      case 'search_nodes':
        validationResult = ToolValidation.validateSearchNodes(args);
        break;
      case 'n8n_create_workflow':
        validationResult = ToolValidation.validateCreateWorkflow(args);
        break;
      case 'n8n_get_workflow':
      case 'n8n_update_full_workflow':
      case 'n8n_delete_workflow':
      case 'n8n_validate_workflow':
      case 'n8n_autofix_workflow':
        validationResult = ToolValidation.validateWorkflowId(args);
        break;
      case 'n8n_executions':
        // action defaults to list; id validation is done in dispatch based on action
        validationResult = { valid: true, errors: [] };
        break;
      case 'n8n_test_workflow':
        validationResult = hasText(args.workflowId)
          ? { valid: true, errors: [] }
          : {
              valid: false,
              errors: [{
                field: 'workflowId',
                message: 'workflowId is required: the ID of the workflow to run ("id" is accepted as an alias)'
              }]
            };
        break;
      case 'n8n_evaluations': {
        // Every action of this tool requires action and workflowId;
        // runId validation is done in dispatch based on action.
        const evalErrors: Array<{ field: string; message: string }> = [];
        if (!args.action) evalErrors.push({ field: 'action', message: 'action is required' });
        if (!args.workflowId) evalErrors.push({ field: 'workflowId', message: 'workflowId is required' });
        validationResult = evalErrors.length === 0
          ? { valid: true, errors: [] }
          : { valid: false, errors: evalErrors };
        break;
      }
      case 'n8n_manage_datatable':
        validationResult = args.action
          ? { valid: true, errors: [] }
          : { valid: false, errors: [{ field: 'action', message: 'action is required' }] };
        break;
      case 'n8n_manage_credentials':
        validationResult = args.action
          ? { valid: true, errors: [] }
          : { valid: false, errors: [{ field: 'action', message: 'action is required' }] };
        break;
      case 'n8n_manage_folders':
      case 'n8n_manage_agents':
        validationResult = args.action
          ? { valid: true, errors: [] }
          : { valid: false, errors: [{ field: 'action', message: 'action is required' }] };
        break;
      case 'n8n_audit_instance':
        // No required parameters - all are optional
        validationResult = { valid: true, errors: [] };
        break;
      case 'n8n_deploy_template':
        // Requires templateId parameter
        validationResult = args.templateId !== undefined
          ? { valid: true, errors: [] }
          : { valid: false, errors: [{ field: 'templateId', message: 'templateId is required' }] };
        break;
      default:
        // For tools not yet migrated to schema validation, use basic validation
        return this.validateToolParamsBasic(toolName, args, legacyRequiredParams || []);
      }
      
      if (!validationResult.valid) {
        const errorMessage = Validator.formatErrors(validationResult, toolName);
        logger.error(`Parameter validation failed for ${toolName}:`, errorMessage);
        throw new ValidationError(errorMessage);
      }
    } catch (error) {
      // Handle validation errors properly
      if (error instanceof ValidationError) {
        throw error; // Re-throw validation errors as-is
      }
      
      // Handle unexpected errors from validation system
      logger.error(`Validation system error for ${toolName}:`, error);
      
      // Provide a user-friendly error message
      const errorMessage = error instanceof Error 
        ? `Internal validation error: ${error.message}`
        : `Internal validation error while processing ${toolName}`;
      
      throw new Error(errorMessage);
    }
  }
  
  /**
   * Legacy parameter validation (fallback)
   */
  private validateToolParamsBasic(toolName: string, args: any, requiredParams: string[]): void {
    const missing: string[] = [];
    const invalid: string[] = [];

    for (const param of requiredParams) {
      if (!(param in args) || args[param] === undefined || args[param] === null) {
        missing.push(param);
      } else if (typeof args[param] === 'string' && args[param].trim() === '') {
        invalid.push(`${param} (empty string)`);
      }
    }

    if (missing.length > 0) {
      throw new Error(`Missing required parameters for ${toolName}: ${missing.join(', ')}. Please provide the required parameters to use this tool.`);
    }

    if (invalid.length > 0) {
      throw new Error(`Invalid parameters for ${toolName}: ${invalid.join(', ')}. String parameters cannot be empty.`);
    }
  }

  /**
   * Validate extracted arguments match expected tool schema
   */
  private validateExtractedArgs(toolName: string, args: any): boolean {
    if (!args || typeof args !== 'object') {
      return false;
    }

    // Look up tool schema across built-in and additional tools so host-injected
    // tools receive the same schema-driven validation as built-ins.
    const tool = this.findToolSchema(toolName);
    if (!tool || !tool.inputSchema) {
      return true; // If no schema, assume valid
    }

    const schema = tool.inputSchema;
    const required = schema.required || [];
    const properties = schema.properties || {};

    // Check all required fields are present
    for (const requiredField of required) {
      if (!(requiredField in args)) {
        logger.debug(`Extracted args missing required field: ${requiredField}`, {
          toolName,
          extractedArgsKeys: Object.keys(args),
          required,
        });
        return false;
      }
    }

    // Check field types match schema
    for (const [fieldName, fieldValue] of Object.entries(args)) {
      if (properties[fieldName]) {
        const expectedType = properties[fieldName].type;
        const actualType = Array.isArray(fieldValue) ? 'array' : typeof fieldValue;

        // Basic type validation
        if (expectedType && expectedType !== actualType) {
          // Special case: number can be coerced from string
          if (expectedType === 'number' && actualType === 'string' && !isNaN(Number(fieldValue))) {
            continue;
          }
          
          // SECURITY (GHSA-wg4g-395p-mqv3): log type mismatch shape only, not the value.
          logger.debug(`Extracted args field type mismatch: ${fieldName}`, {
            toolName,
            expectedType,
            actualType,
          });
          return false;
        }
      }
    }

    // Check for extraneous fields if additionalProperties is false
    if (schema.additionalProperties === false) {
      const allowedFields = Object.keys(properties);
      const extraFields = Object.keys(args).filter(field => !allowedFields.includes(field));
      
      if (extraFields.length > 0) {
        logger.debug(`Extracted args have extra fields`, {
          toolName,
          extraFields,
          allowedFields
        });
        // For n8n compatibility, we'll still consider this valid but log it
      }
    }

    return true;
  }

  /**
   * Coerce mistyped parameters back to their expected types.
   * Workaround for Claude Desktop / Claude.ai MCP client bugs that serialize
   * parameters incorrectly (objects as strings, numbers as strings, etc.).
   *
   * Handles ALL type mismatches based on the tool's inputSchema:
   *   string→object, string→array   : JSON.parse
   *   string→number, string→integer : Number()
   *   string→boolean                : "true"/"false" parsing
   *   number→string, boolean→string : .toString()
   */
  private coerceStringifiedJsonParams(
    toolName: string,
    args: Record<string, any> | undefined
  ): Record<string, any> | undefined {
    if (!args || typeof args !== 'object') return args;

    // Look up tool schema across built-in and additional tools so host-injected
    // tools receive the same client-bug coercion (string→object, string→number,
    // etc.) that built-ins do.
    const tool = this.findToolSchema(toolName);
    if (!tool?.inputSchema?.properties) return args;

    const properties = tool.inputSchema.properties;
    const coerced = { ...args };
    let coercedAny = false;

    for (const [key, value] of Object.entries(coerced)) {
      if (value === undefined || value === null) continue;

      const propSchema = (properties as any)[key];
      if (!propSchema) continue;
      const expectedType = propSchema.type;
      if (!expectedType) continue;

      const actualType = typeof value;

      // Already correct type — skip
      if (expectedType === 'string' && actualType === 'string') continue;
      if ((expectedType === 'number' || expectedType === 'integer') && actualType === 'number') continue;
      if (expectedType === 'boolean' && actualType === 'boolean') continue;
      if (expectedType === 'object' && actualType === 'object' && !Array.isArray(value)) continue;
      if (expectedType === 'array' && Array.isArray(value)) continue;

      // --- Coercion: string value → expected type ---
      if (actualType === 'string') {
        const trimmed = (value as string).trim();

        if (expectedType === 'object' && trimmed.startsWith('{')) {
          try {
            const parsed = JSON.parse(trimmed);
            if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
              coerced[key] = parsed;
              coercedAny = true;
            }
          } catch (e) {
            logger.warn(`Failed to parse string→${expectedType} for param "${key}" in tool "${toolName}"`, {
              error: e instanceof Error ? e.message : String(e),
              valuePreview: trimmed.substring(0, 200),
              valueLength: trimmed.length,
            });
          }
          continue;
        }

        if (expectedType === 'array' && trimmed.startsWith('[')) {
          try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed)) {
              coerced[key] = parsed;
              coercedAny = true;
            }
          } catch (e) {
            logger.warn(`Failed to parse string→${expectedType} for param "${key}" in tool "${toolName}"`, {
              error: e instanceof Error ? e.message : String(e),
              valuePreview: trimmed.substring(0, 200),
              valueLength: trimmed.length,
            });
          }
          continue;
        }

        if (expectedType === 'number' || expectedType === 'integer') {
          const num = Number(trimmed);
          if (!isNaN(num) && trimmed !== '') {
            coerced[key] = expectedType === 'integer' ? Math.trunc(num) : num;
            coercedAny = true;
          }
          continue;
        }

        if (expectedType === 'boolean') {
          if (trimmed === 'true') { coerced[key] = true; coercedAny = true; }
          else if (trimmed === 'false') { coerced[key] = false; coercedAny = true; }
          continue;
        }
      }

      // --- Coercion: number/boolean value → expected string ---
      if (expectedType === 'string' && (actualType === 'number' || actualType === 'boolean')) {
        coerced[key] = String(value);
        coercedAny = true;
        continue;
      }
    }

    if (coercedAny) {
      // SECURITY (GHSA-wg4g-395p-mqv3): log key-level types only, never values.
      logger.warn(`Coerced mistyped params for tool "${toolName}"`, {
        original: Object.fromEntries(
          Object.entries(args).map(([k, v]) => [k, typeof v])
        ),
      });
    }

    return coerced;
  }

  /**
   * `n8n_executions` with action=get but no execution id is the most frequent
   * agent call error in telemetry, and the caller wants the listing. Serve it
   * and say so, rather than failing the call.
   */
  private async listExecutionsInsteadOfGet(args: any): Promise<McpToolResponse> {
    // The policy gate checked this call as `get`; the fallback must not open a
    // listing that a DISABLED_TOOL_OPERATIONS rule has closed.
    if (isOperationDisabled('n8n_executions', 'list')) {
      throw new Error('id is required for action=get');
    }
    const result = await n8nHandlers.handleListExecutions(args, this.instanceContext);
    if (!result.success) return result;
    const scope = hasText(args.workflowId) ? `executions of workflow ${args.workflowId}` : 'recent executions';
    return {
      ...result,
      message: `action=get was called without an execution id, so ${scope} were listed instead. Pass id to get one execution.`
    };
  }

  async executeTool(name: string, args: any): Promise<any> {
    // Ensure args is an object and validate it
    args = args || {};

    // Defense in depth: This should never be reached since CallToolRequestSchema
    // handler already checks disabled tools (line 514-528), but we guard here
    // in case of future refactoring or direct executeTool() calls
    const disabledTools = this.getDisabledTools();
    if (disabledTools.has(name)) {
      throw new Error(`Tool '${name}' is disabled via DISABLED_TOOLS environment variable`);
    }

    // Defense in depth: operation-level check
    const disabledToolOps = this.getDisabledToolOperations();
    const disabledOpsForTool = disabledToolOps.get(name);
    if (disabledOpsForTool && disabledOpsForTool.size > 0) {
      const paramName = TOOL_OPERATION_PARAM[name];
      if (paramName) {
        const requestedOp = resolveRequestedOperation(name, args);
        if (requestedOp && disabledOpsForTool.has(String(requestedOp).toLowerCase())) {
          throw new Error(`Operation '${requestedOp}' on tool '${name}' is disabled by server policy`);
        }
      }
    }

    // SECURITY (GHSA-wg4g-395p-mqv3): log metadata only, not raw arg values.
    logger.info(`Tool execution: ${name}`, summarizeToolCallArgs(args));

    // Validate that args is actually an object
    if (typeof args !== 'object' || args === null) {
      throw new Error(`Invalid arguments for tool ${name}: expected object, got ${typeof args}`);
    }

    const additionalTool = this.additionalToolsByName.get(name);
    if (additionalTool) {
      return additionalTool.handler(args, { instanceContext: this.instanceContext } satisfies AdditionalToolContext);
    }

    switch (name) {
      case 'tools_documentation':
        // No required parameters
        return this.getToolsDocumentation(args.topic, args.depth);
      case 'search_nodes':
        this.validateToolParams(name, args, ['query']);
        // Convert limit to number if provided, otherwise use default
        const limit = args.limit !== undefined ? Number(args.limit) || 20 : 20;
        return this.searchNodes(args.query, limit, {
          mode: args.mode,
          includeExamples: args.includeExamples,
          includeOperations: args.includeOperations,
          source: args.source
        });
      case 'get_node': {
        this.validateToolParams(name, args, ['nodeType']);
        // Retired get_node_essentials / get_node_info vocabulary maps onto mode + detail
        const { mode: nodeMode, detail: nodeDetail } = resolveGetNodeAliases(args.mode, args.detail);
        // Handle consolidated modes: docs, search_properties
        if (nodeMode === 'docs') {
          return this.getNodeDocumentation(args.nodeType);
        }
        if (nodeMode === 'search_properties') {
          if (!args.propertyQuery) {
            throw new Error('propertyQuery is required for mode=search_properties');
          }
          const maxResults = args.maxPropertyResults !== undefined ? Number(args.maxPropertyResults) || 20 : 20;
          return this.searchNodeProperties(args.nodeType, args.propertyQuery, maxResults);
        }
        return this.getNode(
          args.nodeType,
          nodeDetail,
          nodeMode,
          args.includeTypeInfo,
          args.includeExamples,
          args.fromVersion,
          args.toVersion
        );
      }
      case 'validate_node':
        this.validateToolParams(name, args, ['nodeType', 'config']);
        // Ensure config is an object
        if (typeof args.config !== 'object' || args.config === null) {
          logger.warn(`validate_node called with invalid config type: ${typeof args.config}`);
          const validationMode = args.mode || 'full';
          if (validationMode === 'minimal') {
            return {
              nodeType: args.nodeType || 'unknown',
              displayName: 'Unknown Node',
              valid: false,
              missingRequiredFields: [
                'Invalid config format - expected object',
                '🔧 RECOVERY: Use format { "resource": "...", "operation": "..." } or {} for empty config'
              ]
            };
          }
          return {
            nodeType: args.nodeType || 'unknown',
            workflowNodeType: args.nodeType || 'unknown',
            displayName: 'Unknown Node',
            valid: false,
            errors: [{
              type: 'config',
              property: 'config',
              message: 'Invalid config format - expected object',
              fix: 'Provide config as an object with node properties'
            }],
            warnings: [],
            suggestions: [
              '🔧 RECOVERY: Invalid config detected. Fix with:',
              '   • Ensure config is an object: { "resource": "...", "operation": "..." }',
              '   • Use get_node to see required fields for this node type',
              '   • Check if the node type is correct before configuring it'
            ],
            summary: {
              hasErrors: true,
              errorCount: 1,
              warningCount: 0,
              suggestionCount: 3
            }
          };
        }
        // Handle mode parameter
        const validationMode = args.mode || 'full';
        if (validationMode === 'minimal') {
          return this.validateNodeMinimal(args.nodeType, args.config);
        }
        return this.validateNodeConfig(args.nodeType, args.config, 'operation', args.profile);
      case 'get_template':
        this.validateToolParams(name, args, ['templateId']);
        const templateId = Number(args.templateId);
        const templateMode = args.mode || 'full';
        return this.getTemplate(templateId, templateMode);
      case 'search_templates': {
        // Consolidated tool with searchMode parameter
        const searchMode = args.searchMode || 'keyword';
        const searchLimit = Math.min(Math.max(Number(args.limit) || 20, 1), 100);
        const searchOffset = Math.max(Number(args.offset) || 0, 0);

        switch (searchMode) {
          case 'by_nodes':
            if (!args.nodeTypes || !Array.isArray(args.nodeTypes) || args.nodeTypes.length === 0) {
              throw new Error('nodeTypes array is required for searchMode=by_nodes');
            }
            return this.listNodeTemplates(args.nodeTypes, searchLimit, searchOffset);
          case 'by_task':
            if (!args.task) {
              throw new Error('task is required for searchMode=by_task');
            }
            return this.getTemplatesForTask(args.task, searchLimit, searchOffset);
          case 'by_metadata':
            return this.searchTemplatesByMetadata({
              category: args.category,
              complexity: args.complexity,
              maxSetupMinutes: args.maxSetupMinutes ? Number(args.maxSetupMinutes) : undefined,
              minSetupMinutes: args.minSetupMinutes ? Number(args.minSetupMinutes) : undefined,
              requiredService: args.requiredService,
              targetAudience: args.targetAudience
            }, searchLimit, searchOffset);
          case 'patterns':
            return this.getWorkflowPatterns(args.task as string | undefined, searchLimit);
          case 'keyword':
          default:
            if (!args.query) {
              throw new Error('query is required for searchMode=keyword');
            }
            const searchFields = args.fields as string[] | undefined;
            return this.searchTemplates(args.query, searchLimit, searchOffset, searchFields);
        }
      }
      case 'validate_workflow':
        this.validateToolParams(name, args, ['workflow']);
        return this.validateWorkflow(args.workflow, args.options);

      // n8n Management Tools (if API is configured)
      case 'n8n_create_workflow':
        this.validateToolParams(name, args, ['name', 'nodes', 'connections']);
        return n8nHandlers.handleCreateWorkflow(args, this.instanceContext);
      case 'n8n_get_workflow': {
        this.validateToolParams(name, args, ['id']);
        const workflowMode = args.mode || 'full';
        switch (workflowMode) {
          case 'details':
            return n8nHandlers.handleGetWorkflowDetails(args, this.instanceContext);
          case 'structure':
            return n8nHandlers.handleGetWorkflowStructure(args, this.instanceContext);
          case 'minimal':
            return n8nHandlers.handleGetWorkflowMinimal(args, this.instanceContext);
          case 'active':
            return n8nHandlers.handleGetWorkflowActive(args, this.instanceContext);
          case 'filtered':
            // nodeNames is required for this mode; the handler's Zod schema enforces it
            // and returns a graceful "Invalid input" response (consistent with the other modes).
            return n8nHandlers.handleGetWorkflowFiltered(args, this.instanceContext);
          case 'full':
          default:
            return n8nHandlers.handleGetWorkflow(args, this.instanceContext);
        }
      }
      case 'n8n_update_full_workflow':
        this.validateToolParams(name, args, ['id']);
        return n8nHandlers.handleUpdateWorkflow(args, this.repository!, this.instanceContext);
      case 'n8n_update_partial_workflow':
        this.validateToolParams(name, args, ['id', 'operations']);
        return handleUpdatePartialWorkflow(args, this.repository!, this.instanceContext);
      case 'n8n_delete_workflow':
        this.validateToolParams(name, args, ['id']);
        return n8nHandlers.handleDeleteWorkflow(args, this.instanceContext);
      case 'n8n_list_workflows':
        // No required parameters
        return n8nHandlers.handleListWorkflows(args, this.instanceContext);
      case 'n8n_validate_workflow':
        this.validateToolParams(name, args, ['id']);
        await this.ensureInitialized();
        if (!this.repository) throw new Error('Repository not initialized');
        return n8nHandlers.handleValidateWorkflow(args, this.repository, this.instanceContext);
      case 'n8n_autofix_workflow':
        this.validateToolParams(name, args, ['id']);
        await this.ensureInitialized();
        if (!this.repository) throw new Error('Repository not initialized');
        return n8nHandlers.handleAutofixWorkflow(args, this.repository, this.instanceContext);
      case 'n8n_test_workflow': {
        const testArgs = withWorkflowIdAlias(args);
        this.validateToolParams(name, testArgs);
        return n8nHandlers.handleTestWorkflow(testArgs, this.instanceContext);
      }
      case 'n8n_executions': {
        this.validateToolParams(name, args);
        // Agents that only want a listing often omit action or send get without an id.
        // The same normalisation the policy gate uses, so a disabled-operation rule
        // and the dispatch always see the same value.
        const execAction = String(resolveRequestedOperation(name, args));
        switch (execAction) {
          case 'get':
            if (!hasText(args.id)) {
              return this.listExecutionsInsteadOfGet(args);
            }
            return n8nHandlers.handleGetExecution(args, this.instanceContext);
          case 'list':
            return n8nHandlers.handleListExecutions(args, this.instanceContext);
          case 'delete':
            if (!hasText(args.id)) {
              throw new Error('id is required for action=delete');
            }
            return n8nHandlers.handleDeleteExecution(args, this.instanceContext);
          default: {
            const message = `Unknown action: ${execAction}. Valid actions: get, list, delete.`;
            const hint = suggestExecutionsAction(execAction);
            throw new Error(hint ? `${message} ${hint}` : message);
          }
        }
      }
      case 'n8n_evaluations': {
        this.validateToolParams(name, args, ['action', 'workflowId']);
        const evalAction = args.action;
        switch (evalAction) {
          case 'list_runs':
            return n8nHandlers.handleListTestRuns(args, this.instanceContext);
          case 'get_run':
            if (!args.runId) {
              throw new Error('runId is required for action=get_run');
            }
            return n8nHandlers.handleGetTestRun(args, this.instanceContext);
          case 'list_cases':
            if (!args.runId) {
              throw new Error('runId is required for action=list_cases');
            }
            return n8nHandlers.handleListTestCases(args, this.instanceContext);
          case 'run':
            return n8nHandlers.handleTriggerTestRun(args, this.instanceContext);
          case 'cancel':
            if (!args.runId) {
              throw new Error('runId is required for action=cancel');
            }
            return n8nHandlers.handleCancelTestRun(args, this.instanceContext);
          default:
            throw new Error(`Unknown action: ${evalAction}. Valid actions: list_runs, get_run, list_cases, run, cancel`);
        }
      }
      case 'n8n_health_check':
        // No required parameters - supports mode='status' (default) or mode='diagnostic'
        if (args.mode === 'diagnostic') {
          return n8nHandlers.handleDiagnostic({ params: { arguments: args } }, this.instanceContext);
        }
        return n8nHandlers.handleHealthCheck(this.instanceContext);
      case 'n8n_workflow_versions':
        // mode defaults to list in the handler schema; workflowId is filled from id
        return n8nHandlers.handleWorkflowVersions(withWorkflowIdAlias(args), this.repository!, this.instanceContext);

      case 'n8n_deploy_template':
        this.validateToolParams(name, args, ['templateId']);
        await this.ensureInitialized();
        if (!this.templateService) throw new Error('Template service not initialized');
        if (!this.repository) throw new Error('Repository not initialized');
        return n8nHandlers.handleDeployTemplate(args, this.templateService, this.repository, this.instanceContext);

      case 'n8n_manage_datatable': {
        this.validateToolParams(name, args, ['action']);
        const dtAction = args.action;
        // Each handler validates its own inputs via Zod schemas
        switch (dtAction) {
          case 'createTable':  return n8nHandlers.handleCreateTable(args, this.instanceContext);
          case 'listTables':   return n8nHandlers.handleListTables(args, this.instanceContext);
          case 'getTable':     return n8nHandlers.handleGetTable(args, this.instanceContext);
          case 'updateTable':  return n8nHandlers.handleUpdateTable(args, this.instanceContext);
          case 'deleteTable':  return n8nHandlers.handleDeleteTable(args, this.instanceContext);
          case 'getRows':      return n8nHandlers.handleGetRows(args, this.instanceContext);
          case 'insertRows':   return n8nHandlers.handleInsertRows(args, this.instanceContext);
          case 'updateRows':   return n8nHandlers.handleUpdateRows(args, this.instanceContext);
          case 'upsertRows':   return n8nHandlers.handleUpsertRows(args, this.instanceContext);
          case 'deleteRows':   return n8nHandlers.handleDeleteRows(args, this.instanceContext);
          // Column actions need n8n's own MCP server - the Public API cannot
          // change a table's schema after creation.
          case 'addColumn':    return n8nHandlers.handleAddColumn(args, this.instanceContext);
          case 'deleteColumn': return n8nHandlers.handleDeleteColumn(args, this.instanceContext);
          case 'renameColumn': return n8nHandlers.handleRenameColumn(args, this.instanceContext);
          default:
            throw new Error(`Unknown action: ${dtAction}. Valid actions: createTable, listTables, getTable, updateTable, deleteTable, getRows, insertRows, updateRows, upsertRows, deleteRows, addColumn, deleteColumn, renameColumn`);
        }
      }

      case 'n8n_manage_folders': {
        this.validateToolParams(name, args, ['action']);
        const folderAction = args.action;
        // Each handler validates its own inputs via Zod schemas
        switch (folderAction) {
          case 'create': return n8nHandlers.handleCreateFolder(args, this.instanceContext);
          case 'list':   return n8nHandlers.handleListFolders(args, this.instanceContext);
          case 'get':    return n8nHandlers.handleGetFolder(args, this.instanceContext);
          case 'rename': return n8nHandlers.handleRenameFolder(args, this.instanceContext);
          case 'move':   return n8nHandlers.handleMoveFolder(args, this.instanceContext);
          case 'delete': return n8nHandlers.handleDeleteFolder(args, this.instanceContext);
          default:
            throw new Error(`Unknown action: ${folderAction}. Valid actions: create, list, get, rename, move, delete`);
        }
      }

      case 'n8n_manage_agents':
        this.validateToolParams(name, args, ['action']);
        return handleManageAgents(args, this.instanceContext);

      case 'n8n_explore_node_resources':
        return handleExploreNodeResources(args, this.instanceContext);

      case 'n8n_list_catalog':
        this.validateToolParams(name, args, ['kind']);
        return handleListCatalog(args, this.instanceContext);

      case 'n8n_manage_credentials': {
        this.validateToolParams(name, args, ['action']);
        const credAction = args.action;
        switch (credAction) {
          case 'list':      return n8nHandlers.handleListCredentials(args, this.instanceContext);
          case 'get':       return n8nHandlers.handleGetCredential(args, this.instanceContext);
          case 'create':    return n8nHandlers.handleCreateCredential(args, this.instanceContext);
          case 'update':    return n8nHandlers.handleUpdateCredential(args, this.instanceContext);
          case 'delete':    return n8nHandlers.handleDeleteCredential(args, this.instanceContext);
          case 'getSchema': return n8nHandlers.handleGetCredentialSchema(args, this.instanceContext);
          default:
            throw new Error(`Unknown action: ${credAction}. Valid actions: list, get, create, update, delete, getSchema`);
        }
      }

      case 'n8n_audit_instance':
        // No required parameters - all are optional
        return n8nHandlers.handleAuditInstance(args, this.instanceContext);

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async listNodes(filters: any = {}): Promise<any> {
    await this.ensureInitialized();
    
    let query = 'SELECT * FROM nodes WHERE 1=1';
    const params: any[] = [];
    
    // console.log('DEBUG list_nodes:', { filters, query, params }); // Removed to prevent stdout interference

    if (filters.package) {
      // Handle both formats
      const packageVariants = [
        filters.package,
        `@n8n/${filters.package}`,
        filters.package.replace('@n8n/', '')
      ];
      query += ' AND package_name IN (' + packageVariants.map(() => '?').join(',') + ')';
      params.push(...packageVariants);
    }

    if (filters.category) {
      query += ' AND category = ?';
      params.push(filters.category);
    }

    if (filters.developmentStyle) {
      query += ' AND development_style = ?';
      params.push(filters.developmentStyle);
    }

    if (filters.isAITool !== undefined) {
      query += ' AND is_ai_tool = ?';
      params.push(filters.isAITool ? 1 : 0);
    }

    query += ' ORDER BY display_name';

    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    }

    const nodes = this.db!.prepare(query).all(...params) as NodeRow[];
    
    return {
      nodes: nodes.map(node => ({
        nodeType: node.node_type,
        displayName: node.display_name,
        description: node.description,
        category: node.category,
        package: node.package_name,
        developmentStyle: node.development_style,
        isAITool: Number(node.is_ai_tool) === 1,
        isTrigger: Number(node.is_trigger) === 1,
        isVersioned: Number(node.is_versioned) === 1,
      })),
      totalCount: nodes.length,
    };
  }

  private async getNodeInfo(nodeType: string): Promise<any> {
    await this.ensureInitialized();
    if (!this.repository) throw new Error('Repository not initialized');

    // First try with normalized type (repository will also normalize internally)
    const normalizedType = NodeTypeNormalizer.normalizeToFullForm(nodeType);
    let node = this.repository.getNode(normalizedType);
    
    if (!node && normalizedType !== nodeType) {
      // Try original if normalization changed it
      node = this.repository.getNode(nodeType);
    }
    
    if (!node) {
      // Fallback to other alternatives for edge cases
      const alternatives = getNodeTypeAlternatives(normalizedType);
      
      for (const alt of alternatives) {
        const found = this.repository!.getNode(alt);
        if (found) {
          node = found;
          break;
        }
      }
    }
    
    if (!node) {
      throw new Error(`Node ${nodeType} not found`);
    }
    
    // N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE gates community packages being
    // used as tools at all, so the requirement follows the community flag -
    // not the AI-tool flag (which can be inferred, #954) and not a package-name
    // test (which would sweep in first-party @n8n/* packages, #955).
    const isCommunityNode = node.isCommunity ?? false;
    const isMarkedAsAITool = node.isAITool ?? false;

    // Built-in flags come from the declared usableAsTool property. Community
    // ingestion collapses a declared usableAsTool and the package's codex AI
    // category into one flag, so for community nodes the two are not
    // distinguishable after the fact - the value says exactly that.
    let aiToolFlagSource: string | null = null;
    if (isMarkedAsAITool) {
      aiToolFlagSource = isCommunityNode ? 'declared-or-ai-category' : 'declared-property';
    }

    const aiToolCapabilities = {
      canBeUsedAsTool: true, // Any node can be used as a tool in n8n
      hasUsableAsToolProperty: isMarkedAsAITool,
      aiToolFlagSource,
      requiresEnvironmentVariable: isCommunityNode,
      toolConnectionType: 'ai_tool',
      commonToolUseCases: this.getCommonAIToolUseCases(node.nodeType),
      environmentRequirement: isCommunityNode
        ? 'N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true'
        : null
    };

    // Process outputs to provide clear mapping with null safety
    let outputs = undefined;
    if (node.outputNames && Array.isArray(node.outputNames) && node.outputNames.length > 0) {
      outputs = node.outputNames.map((name: string, index: number) => {
        // Special handling for loop nodes like SplitInBatches
        const descriptions = this.getOutputDescriptions(node.nodeType, name, index);
        return {
          index,
          name,
          description: descriptions?.description ?? '',
          connectionGuidance: descriptions?.connectionGuidance ?? ''
        };
      });
    }

    const result: any = {
      ...node,
      workflowNodeType: getWorkflowNodeType(node.package ?? 'n8n-nodes-base', node.nodeType),
      aiToolCapabilities,
      outputs
    };

    // Add tool variant guidance if applicable
    const toolVariantInfo = this.buildToolVariantGuidance(node);
    if (toolVariantInfo) {
      result.toolVariantInfo = toolVariantInfo;
    }

    return result;
  }

  /**
   * Primary search method used by ALL MCP search tools.
   *
   * This method automatically detects and uses FTS5 full-text search when available
   * (lines 1189-1203), falling back to LIKE queries only if FTS5 table doesn't exist.
   *
   * NOTE: This is separate from NodeRepository.searchNodes() which is legacy LIKE-based.
   * All MCP tool invocations route through this method to leverage FTS5 performance.
   */
  private async searchNodes(
    query: string,
    limit: number = 20,
    options?: {
      mode?: 'OR' | 'AND' | 'FUZZY';
      includeSource?: boolean;
      includeExamples?: boolean;
      includeOperations?: boolean;
      source?: 'all' | 'core' | 'community' | 'verified';
    }
  ): Promise<any> {
    await this.ensureInitialized();
    if (!this.db) throw new Error('Database not initialized');

    // Normalize the query if it looks like a full node type
    let normalizedQuery = query;
    
    // Check if query contains node type patterns and normalize them
    if (query.includes('n8n-nodes-base.') || query.includes('@n8n/n8n-nodes-langchain.')) {
      normalizedQuery = query
        .replace(/n8n-nodes-base\./g, 'nodes-base.')
        .replace(/@n8n\/n8n-nodes-langchain\./g, 'nodes-langchain.');
    }
    
    const searchMode = options?.mode || 'OR';
    
    // Check if FTS5 table exists
    const ftsExists = this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='nodes_fts'
    `).get();
    
    if (ftsExists) {
      // Use FTS5 search with normalized query
      logger.debug(`Using FTS5 search with includeExamples=${options?.includeExamples}`);
      return this.searchNodesFTS(normalizedQuery, limit, searchMode, options);
    } else {
      // Fallback to LIKE search with normalized query
      logger.debug('Using LIKE search (no FTS5)');
      return this.searchNodesLIKE(normalizedQuery, limit, options);
    }
  }

  private async searchNodesFTS(
    query: string,
    limit: number,
