/**
 * GlueError - Canonical error envelope
 */

export enum ErrorCode {
  // Auth/Access
  AUTH_REQUIRED = 'auth_required',
  ACCESS_DENIED = 'access_denied',
  QUOTA_REACHED = 'quota_reached',
  POLICY_VIOLATION = 'policy_violation',
  // Resource
  NOT_FOUND = 'not_found',
  ALREADY_EXISTS = 'already_exists',
  INVALID_STATE = 'invalid_state',
  // Contract
  COMPILE_ERROR = 'compile_error',
  VALIDATION_ERROR = 'validation_error',
  EXECUTION_ERROR = 'execution_error',
  // Input
  INVALID_INPUT = 'invalid_input',
  MISSING_REQUIRED = 'missing_required',
  TYPE_MISMATCH = 'type_mismatch',
  // System
  INTERNAL_ERROR = 'internal_error',
  TIMEOUT = 'timeout',
  UNAVAILABLE = 'unavailable',
}

export class GlueError extends Error {
  readonly code: ErrorCode;
  readonly detail?: string;
  readonly hints: string[];
  readonly docs?: string;
  readonly status?: number;
  readonly retryable: boolean;

  constructor(
    code: ErrorCode,
    message: string,
    detail?: string,
    hints: string[] = [],
    docs?: string,
    status?: number,
    retryable = false
  ) {
    super(message);
    this.name = 'GlueError';
    this.code = code;
    this.detail = detail;
    this.hints = hints;
    this.docs = docs;
    this.status = status;
    this.retryable = retryable;
  }

  static notFound(what: string): GlueError {
    return new GlueError(ErrorCode.NOT_FOUND, `${what} not found`);
  }

  static compileError(msg: string, detail?: string): GlueError {
    return new GlueError(ErrorCode.COMPILE_ERROR, msg, detail);
  }

  static invalidInput(msg: string): GlueError {
    return new GlueError(ErrorCode.INVALID_INPUT, msg);
  }

  static policyViolation(policy: string, reason: string): GlueError {
    return new GlueError(
      ErrorCode.POLICY_VIOLATION,
      `Policy '${policy}' violated: ${reason}`
    );
  }

  static fromResponse(data: Record<string, unknown>): GlueError {
    const error = (data.error as Record<string, unknown>) || data;
    const codeStr = (error.code as string) || 'internal_error';
    const code = Object.values(ErrorCode).includes(codeStr as ErrorCode)
      ? (codeStr as ErrorCode)
      : ErrorCode.INTERNAL_ERROR;

    return new GlueError(
      code,
      (error.message as string) || 'Unknown error',
      error.detail as string | undefined,
      (error.hints as string[]) || (error.hint as string[]) || [],
      error.docs as string | undefined,
      error.status as number | undefined,
      Boolean(error.retryable)
    );
  }
}
