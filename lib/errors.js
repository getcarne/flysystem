// flysystem errors: StorageError + FilesystemPolicyError.
// Mirrors Nim core.nim StorageError and policy.nim FilesystemPolicyError
// (which carries {operation, rule}).

/**
 * Base error for everything flysystem refuses to do.
 *
 * You will see this when a path escapes the sandbox, a file is
 * missing, or a write fails halfway. Check `err.message`, it always
 * names the path involved.
 */
class StorageError extends Error {
  /**
   * Creates a storage error.
   * @param {string} message - What went wrong, with the path in it.
   */
  constructor(message) {
    super(message);
    this.name = "StorageError";
  }
}

/**
 * Policy refusal. A nicer StorageError that also tells you which
 * rule said no and which operation tripped it.
 *
 * Example: write a `.exe` when only `["txt"]` is allowed gives
 * `{operation: "write", rule: "allowedExtensions"}`.
 */
class FilesystemPolicyError extends StorageError {
  /**
   * Creates a policy error.
   * @param {string} operation - What you tried ("read", "write", ...).
   * @param {string} rule - Which rule blocked it ("readOnly", "maxFileSize", ...).
   * @param {string} detail - Plain-language explanation.
   */
  constructor(operation, rule, detail) {
    super("policy violation [" + rule + "]: " + operation + " " + detail);
    this.name = "FilesystemPolicyError";
    this.operation = operation;
    this.rule = rule;
  }
}

module.exports = { StorageError, FilesystemPolicyError };
