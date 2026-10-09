import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { capabilities } from '../core/index.js';
import { APP_VERSION } from '../core/version.js';
import { ENGINES, allEngines } from '../core/engines.js';
import './engines-server.js';
import { serializeError } from '../core/errors.js';
import { decodeRequest, encodeResult, MAX_BASE64, MAX_JSON, UNPACK_MODES } from './transport.js';
import { MAX_CONCURRENCY, runJob } from './jobs.js';

const server = new McpServer({ name: 'oldershellsck', version: APP_VERSION });
const reply = object => ({ content: [{ type: 'text', text: JSON.stringify(object) }], structuredContent: object });
let active = 0;
// Factories, not shared instances: zod-to-json-schema emits $ref for any
// schema used twice, which hides type/minimum/maximum from naive clients.
const u32 = () => z.number().int().min(0).max(0xffffffff);
const samples = () => z.array(z.number()).min(1).max(128);
const probeSize = () => z.union([z.literal(2), z.literal(5), z.literal(6)]);
const armadilloSchema = {
  probes: z.array(z.object({
    address: u32(), size: probeSize(), samples: samples().optional(),
  }).strict()).min(1).max(32).optional(),
  probePlan: z.object({
    imageBase: u32(),
    probes: z.array(z.object({ address: u32(), size: probeSize(), samples: samples() }).strict()).min(1).max(32),
  })
    .strict().refine(plan => plan.probes.every(probe => probe.address >= plan.imageBase), { message: 'probe address below imageBase' }).optional(),
  timeoutSeconds: z.number().finite().min(0.1).max(60).optional(),
  maxEvents: z.number().int().min(16).max(50000).optional(),
  sampleArgs: z.array(z.string().max(4096).refine(arg => !arg.includes('\0'), { message: 'NUL in sample argument' })).max(32).optional(),
  imageBase: u32().optional(),
};
server.registerTool('list_capabilities', { description: 'List exact implemented unpackers, DIE subset scope, limits and research-only catalog.', inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false } }, async () => reply(capabilities()));
for (const operation of ['analyze', 'unpack']) {
  server.registerTool(`${operation}_file`, {
    description: operation === 'analyze' ? 'Statically inspect PE bytes. Does not execute files. DIE rules are a documented subset.' : 'Select a supported static unpacker, or auto-detect one. Returns base64 PE with outputKind and unrecovered structures. analysis-pe is not runnable; all outputs are runtime-unverified.',
    inputSchema: { dataBase64: z.string().min(4).max(MAX_BASE64), name: z.string().max(256).optional(), ...(operation === 'unpack' ? { engine: z.enum(['auto', ...allEngines().map(engine => engine.metadata.id)]).optional(), oepRva: z.number().int().positive().max(0xFFFFFFF).optional(), mode: z.enum(UNPACK_MODES).optional(), ...armadilloSchema } : {}) },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async args => {
    if (active >= MAX_CONCURRENCY) return { ...reply({ error: { code: 'busy' } }), isError: true };
    active++;
    try {
      const { bytes, options } = decodeRequest(args);
      return reply(encodeResult(await runJob(operation, bytes, options)));
    } catch (error) { return { ...reply({ error: serializeError(error) }), isError: true }; }
    finally { active--; }
  });
}
// SDK 1.32 defaults to a 10 MiB frame, smaller than our advertised input limit.
await server.connect(new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: MAX_JSON }));
