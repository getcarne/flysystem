// flysystem Filesystem: multi-disk facade. Port of Nim filesystem.nim.
// Disks are LocalDriver (or policy-wrapped) instances keyed by name.
//
// Think of it as a tiny switchboard: you register named disks once
// ("local", "cache", ...) and then talk to the default disk without
// caring where it lives. Ask for `.disk("cache")` when you need
// another one on purpose.

const { StorageError } = require("./errors.js");
const { defaultPolicyRules, FilesystemPolicy } = require("./policy.js");

/**
 * True when a rules object is just the defaults (nothing enforced).
 * Used to skip the policy wrapper entirely for speed.
 * @param {object} rules - Rules to compare against defaults.
 * @returns {boolean} True when no rule is active.
 */
function isDefaultPolicy(rules) {
  var d = defaultPolicyRules();
  return rules.readOnly === d.readOnly &&
    rules.maxFileSize === d.maxFileSize &&
    rules.maxPathLength === d.maxPathLength &&
    rules.maxDepth === d.maxDepth &&
    rules.denyHiddenFiles === d.denyHiddenFiles &&
    (rules.allowedExtensions || []).length === 0 &&
    (rules.allowedMimeTypes || []).length === 0;
}

/**
 * Named collection of disks with one default you rarely name.
 * Every shortcut method below just forwards to the default disk.
 */
class Filesystem {
  /**
   * Creates an empty switchboard.
   * @param {string} [defaultDisk] - Name used when no disk is given. Defaults to "local".
   */
  constructor(defaultDisk) {
    this.disks = {};
    this.policies = {};
    this.defaultDisk = defaultDisk || "local";
  }

  /**
   * Plugs a driver in under a name, with optional guard rails.
   * @param {string} name - Disk name ("local", "cache", ...).
   * @param {object} driver - LocalDriver (or compatible) instance.
   * @param {object} [policy] - Partial policy rules for this disk.
   * @returns {void}
   */
  addDisk(name, driver, policy) {
    this.disks[name] = driver;
    this.policies[name] = policy ? Object.assign(defaultPolicyRules(), policy) : defaultPolicyRules();
  }

  /**
   * Gets a disk by name, wrapped in its policy when one is active.
   * @param {string} [name] - Disk name, defaults to the default disk.
   * @returns {object} Driver (possibly policy-wrapped).
   */
  disk(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.disks)) throw new StorageError("Disk not found: " + key);
    var policy = this.policies[key] || defaultPolicyRules();
    if (isDefaultPolicy(policy)) return this.disks[key];
    return new FilesystemPolicy(this.disks[key], policy);
  }

  /**
   * Gets the raw driver, skipping any policy wrapper.
   * Handy for admin tasks like cleanup.
   * @param {string} [name] - Disk name, defaults to the default disk.
   * @returns {object} Unwrapped driver.
   */
  rawDisk(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.disks)) throw new StorageError("Disk not found: " + key);
    return this.disks[key];
  }

  /**
   * Shows the policy rules stored for a disk.
   * @param {string} [name] - Disk name, defaults to the default disk.
   * @returns {object} Copy of the rules object.
   */
  diskPolicy(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.policies)) throw new StorageError("Disk not found: " + key);
    return this.policies[key];
  }

  /**
   * Writes a file on the default disk.
   * @param {string} path - Destination path.
   * @param {string|Uint8Array} content - Text or bytes.
   * @param {string} [visibility] - "public" or "private".
   * @returns {void}
   */
  write(path, content, visibility) {
    return this.disk().write(path, content, visibility);
  }

  /**
   * Reads a file as text from the default disk.
   * @param {string} path - File path.
   * @returns {string} File content.
   */
  read(path) {
    return this.disk().read(path);
  }

  /**
   * Checks whether a path exists on the default disk.
   * @param {string} path - Path to check.
   * @returns {boolean} True when present.
   */
  exists(path) {
    return this.disk().exists(path);
  }

  /**
   * Deletes a file on the default disk.
   * @param {string} path - File path.
   * @returns {void}
   */
  delete(path) {
    return this.disk().delete(path);
  }

  /**
   * Lists a folder on the default disk.
   * @param {string} path - Folder path.
   * @param {boolean} [recursive] - Walk subfolders too.
   * @returns {Array} Entries with path, size and dates.
   */
  list(path, recursive) {
    return this.disk().list(path, recursive);
  }

  /**
   * Moves a file on the default disk.
   * @param {string} src - Source path.
   * @param {string} dest - Destination path.
   * @returns {void}
   */
  move(src, dest) {
    return this.disk().move(src, dest);
  }

  /**
   * Copies a file on the default disk.
   * @param {string} src - Source path.
   * @param {string} dest - Destination path.
   * @returns {void}
   */
  copy(src, dest) {
    return this.disk().copy(src, dest);
  }

  /**
   * Creates a folder (parents included) on the default disk.
   * @param {string} path - Folder path.
   * @returns {void}
   */
  makeDir(path) {
    return this.disk().makeDir(path);
  }

  /**
   * Removes a folder on the default disk.
   * @param {string} path - Folder path.
   * @param {boolean} [force] - Remove even when not empty.
   * @returns {void}
   */
  deleteDir(path, force) {
    return this.disk().deleteDir(path, force);
  }
}

/**
 * Creates an empty filesystem switchboard.
 * @param {string} [defaultDisk] - Name of the default disk. Defaults to "local".
 * @returns {Filesystem} Ready to have disks added.
 */
function newFilesystem(defaultDisk) {
  return new Filesystem(defaultDisk);
}

module.exports = { Filesystem, newFilesystem };
