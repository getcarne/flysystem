// flysystem errors: StorageError + FilesystemPolicyError.
// Mirrors Nim core.nim StorageError and policy.nim FilesystemPolicyError
// (which carries {operation, rule}).

class StorageError extends Error {
  constructor(message) {
    super(message);
    this.name = "StorageError";
  }
}

class FilesystemPolicyError extends StorageError {
  constructor(operation, rule, detail) {
    super("policy violation [" + rule + "]: " + operation + " " + detail);
    this.name = "FilesystemPolicyError";
    this.operation = operation;
    this.rule = rule;
  }
}

module.exports = { StorageError, FilesystemPolicyError };
