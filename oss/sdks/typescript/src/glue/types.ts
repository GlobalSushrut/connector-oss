/**
 * Strict typed Glue grammar - verbs, nouns, and validation
 */

export enum GlueVerb {
  // Core operations
  RUN = 'run',
  REMEMBER = 'remember',
  RECALL = 'recall',
  SEARCH = 'search',
  SHOW = 'show',
  LIST = 'list',
  AUDIT = 'audit',
  VERIFY = 'verify',
  
  // Agent operations
  START = 'start',
  STOP = 'stop',
  STATUS = 'status',
  PAUSE = 'pause',
  RESUME = 'resume',
  DEPLOY = 'deploy',
  
  // Memory operations
  WRITE = 'write',
  READ = 'read',
  RANGE = 'range',
  
  // Tool operations
  CALL = 'call',
  INFO = 'info',
  
  // Policy operations
  BIND = 'bind',
  CHECK = 'check',
  
  // Infra operations
  EXPLAIN = 'explain',
  PROVE = 'prove',
  TRACE = 'trace',
  REVIEW = 'review',
  COST = 'cost',
  HEALTH = 'health',
  DOCTOR = 'doctor',
  LOGS = 'logs',
  BACKUP = 'backup',
  RESTORE = 'restore',
  UPGRADE = 'upgrade',
}

export enum GlueNoun {
  // Execution
  CONTRACT = 'contract',
  AGENT = 'agent',
  EXECUTION = 'execution',
  
  // Memory
  MEMORY = 'memory',
  KNOWLEDGE = 'knowledge',
  SESSION = 'session',
  
  // Tools & Policy
  TOOL = 'tool',
  POLICY = 'policy',
  
  // Compliance & Proof
  COMPLIANCE = 'compliance',
  PROOF = 'proof',
  RECEIPT = 'receipt',
  
  // Infrastructure
  NODE = 'node',
  PROTOCOL = 'protocol',
  MONITOR = 'monitor',
  INFRA = 'infra',
}

export type GlueVerbType = `${GlueVerb}`;
export type GlueNounType = `${GlueNoun}`;
