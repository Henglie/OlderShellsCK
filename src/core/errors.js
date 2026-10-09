export class AnalysisError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'AnalysisError';
    this.code = code;
    this.details = details;
  }
}

export function requireThat(condition, code, details = {}) {
  if (!condition) throw new AnalysisError(code, details);
}

export function serializeError(error) {
  return { code: error.code || 'internal-error', details: error.details || {} };
}
