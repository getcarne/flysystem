// flysystem Filesystem: multi-disk facade. Port of Nim filesystem.nim.
// Disks are LocalDriver (or policy-wrapped) instances keyed by name.

const { StorageError } = require("./errors.js");
const { defaultPolicyRules, FilesystemPolicy } = require("./policy.js");

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

class Filesystem {
  constructor(defaultDisk) {
    this.disks = {};
    this.policies = {};
    this.defaultDisk = defaultDisk || "local";
  }

  addDisk(name, driver, policy) {
    this.disks[name] = driver;
    this.policies[name] = policy ? Object.assign(defaultPolicyRules(), policy) : defaultPolicyRules();
  }

  disk(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.disks)) throw new StorageError("Disk not found: " + key);
    var policy = this.policies[key] || defaultPolicyRules();
    if (isDefaultPolicy(policy)) return this.disks[key];
    return new FilesystemPolicy(this.disks[key], policy);
  }

  rawDisk(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.disks)) throw new StorageError("Disk not found: " + key);
    return this.disks[key];
  }

  diskPolicy(name) {
    var key = name && name.length > 0 ? name : this.defaultDisk;
    if (!(key in this.policies)) throw new StorageError("Disk not found: " + key);
    return this.policies[key];
  }

  write(path, content, visibility) { return this.disk().write(path, content, visibility); }
  read(path) { return this.disk().read(path); }
  exists(path) { return this.disk().exists(path); }
  delete(path) { return this.disk().delete(path); }
  list(path, recursive) { return this.disk().list(path, recursive); }
  move(src, dest) { return this.disk().move(src, dest); }
  copy(src, dest) { return this.disk().copy(src, dest); }
  makeDir(path) { return this.disk().makeDir(path); }
  deleteDir(path, force) { return this.disk().deleteDir(path, force); }
}

function newFilesystem(defaultDisk) {
  return new Filesystem(defaultDisk);
}

module.exports = { Filesystem, newFilesystem };
