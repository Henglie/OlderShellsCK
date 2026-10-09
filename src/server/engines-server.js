// Server-side engine registration side effect. Imported by http.js, mcp.js
// and job-worker.js so every server entry point sees the external-tool engine.
import { registerServerEngine } from '../core/engines.js';
import { rebuildCatalog } from '../core/catalog.js';
import { UPX_TOOL_ENGINE, unpackUpxTool, supportsUpxTool } from '../core/unpackers/upx-tool.js';
import { DYNAMIC_ENGINE, unpackDynamic, supportsDynamic } from '../core/unpackers/dynamic.js';
import { EMULATED_ENGINE, unpackEmulated, supportsEmulated } from '../core/unpackers/emulated.js';
import { INSTRUMENT_ENGINE, unpackInstrumented } from '../core/unpackers/instrument.js';
import { ASPACK_ENGINE, unpackAspack, supportsAspack } from '../core/unpackers/aspack.js';
import { MEW_ENGINE, unpackMew, supportsMew } from '../core/unpackers/mew.js';
import { ARMA_ENGINE, unpackArmadillo, supportsArmadillo } from '../core/unpackers/armadillo-engine.js';

registerServerEngine({ metadata: UPX_TOOL_ENGINE, supports: supportsUpxTool, unpack: unpackUpxTool });
registerServerEngine({ metadata: DYNAMIC_ENGINE, supports: supportsDynamic, unpack: (bytes, name, options) => unpackDynamic(bytes, name, options) });
registerServerEngine({ metadata: EMULATED_ENGINE, supports: supportsEmulated, unpack: unpackEmulated });
registerServerEngine({ metadata: INSTRUMENT_ENGINE, supports: () => false, unpack: unpackInstrumented });
registerServerEngine({ metadata: ASPACK_ENGINE, supports: supportsAspack, unpack: unpackAspack });
registerServerEngine({ metadata: MEW_ENGINE, supports: supportsMew, unpack: unpackMew });
registerServerEngine({ metadata: ARMA_ENGINE, supports: supportsArmadillo, unpack: unpackArmadillo });
rebuildCatalog();
