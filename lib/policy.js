// flysystem policy: FilesystemPolicy wraps any driver and enforces
// PolicyRules. Port of Nim policy.nim (read-only, size caps, path
// limits, hidden-file denial, extension/MIME allowlists).

const mimetype = require("std/mimetype");
const { StorageError, FilesystemPolicyError } = require("./errors.js");

/**
 * Default policy rules. Zero / empty means "no limit".
 * @returns {{readOnly: boolean, maxFileSize: number, maxPathLength: number, maxDepth: number, denyHiddenFiles: boolean, allowedExtensions: string[], allowedMimeTypes: string[]}} Fresh rules object.
 */
function defaultPolicyRules() {
  return {
    readOnly: false,
    maxFileSize: 0,
    maxPathLength: 0,
    maxDepth: 0,
    denyHiddenFiles: false,
    allowedExtensions: [],
    allowedMimeTypes: [],
  };
}

/**
 * Last path segment after `/`.
 * @param {string} p - Path to split.
 * @returns {string} Basename.
 */
function basename(p) {
  var idx = p.lastIndexOf("/");
  return idx === -1 ? p : p.slice(idx + 1);
}

/**
 * Lowercase file extension without the dot.
 * @param {string} path - Path to inspect.
 * @returns {string} Extension or "" when none.
 */
function extOf(path) {
  var base = basename(path);
  var dot = base.lastIndexOf(".");
  if (dot === -1) return "";
  return base.slice(dot + 1).toLowerCase();
}

/**
 * MIME type for a path via its extension.
 * @param {string} path - Path to inspect.
 * @returns {string} MIME type, `application/octet-stream` fallback.
 */
function mimeOf(path) {
  var ext = extOf(path);
  if (ext === "") return "application/octet-stream";
  try {
    var t = mimetype.lookup(ext);
    return t === null || t === undefined ? "application/octet-stream" : t;
  } catch (_) {
    return "application/octet-stream";
  }
}

/**
 * Throws a policy violation.
 * @param {string} operation - Operation name (e.g. "read").
 * @param {string} rule - Rule name (e.g. "readOnly").
 * @param {string} detail - Human-readable detail.
 * @returns {void} Never returns, always throws.
 */
function policyError(operation, rule, detail) {
  throw new FilesystemPolicyError(operation, rule, detail);
}

/**
 * Policy wrapper around any driver. Reads enforce path, hidden,
 * extension, MIME and size rules. Writes additionally enforce
 * read-only mode.
 */
class FilesystemPolicy {
  /**
   * Wraps an inner driver with policy rules.
   * @param {object} inner - Inner driver (LocalDriver or compatible).
   * @param {object} [rules] - Partial rules, merged over defaults.
   */
  constructor(inner, rules) {
    if (!inner) throw new StorageError("FilesystemPolicy requires an inner driver");
    this.inner = inner;
    this.rules = Object.assign(defaultPolicyRules(), rules || {});
  }

  /**
   * Rejects writes when read-only mode is on.
   * @param {string} operation - Operation name.
   * @returns {void} Throws on violation.
   */
  checkWritable(operation) {
    if (this.rules.readOnly) policyError(operation, "readOnly", "is not allowed in read-only mode");
  }

  /**
   * Enforces max path length and max depth.
   * @param {string} operation - Operation name.
   * @param {string} path - Path to check.
   * @returns {void} Throws on violation.
   */
  checkPath(operation, path) {
    if (this.rules.maxPathLength > 0 && path.length > this.rules.maxPathLength) {
      policyError(operation, "maxPathLength", "path of " + path.length + " chars exceeds limit of " + this.rules.maxPathLength);
    }
    if (this.rules.maxDepth > 0) {
      var depth = String(path).split("/").length;
      if (depth > this.rules.maxDepth) {
        policyError(operation, "maxDepth", "path depth of " + depth + " exceeds limit of " + this.rules.maxDepth);
      }
    }
  }

  /**
   * True when the basename starts with a dot.
   * @param {string} path - Path to check.
   * @returns {boolean} Hidden or not.
   */
  isHidden(path) {
    var name = basename(path);
    return name.length > 0 && name[0] === ".";
  }

  /**
   * Rejects hidden paths when denyHiddenFiles is on.
   * @param {string} operation - Operation name.
   * @param {string} path - Path to check.
   * @returns {void} Throws on violation.
   */
  checkHidden(operation, path) {
    if (this.rules.denyHiddenFiles && this.isHidden(path)) {
      policyError(operation, "denyHiddenFiles", "hidden path: '" + path + "'");
    }
  }

  /**
   * True when the path resolves to a directory.
   * @param {string} path - Path to check.
   * @returns {boolean} False when missing or not a directory.
   */
  isDirPath(path) {
    try {
      return this.inner.metadata(path).isDir;
    } catch (_) {
      return false;
    }
  }

  /**
   * Enforces the extension allowlist. Directories skip via checkAccess.
   * @param {string} operation - Operation name.
   * @param {string} path - Path to check.
   * @returns {void} Throws on violation.
   */
  checkExtension(operation, path) {
    if (this.rules.allowedExtensions.length > 0) {
      var ext = extOf(path);
      var allowed = this.rules.allowedExtensions.map(function (e) { return String(e).toLowerCase(); });
      if (ext === "" || allowed.indexOf(ext) === -1) {
        policyError(operation, "allowedExtensions", "extension not allowed: '" + path + "'");
      }
    }
  }

  /**
   * Enforces the MIME allowlist. Directories skip via checkAccess.
   * @param {string} operation - Operation name.
   * @param {string} path - Path to check.
   * @returns {void} Throws on violation.
   */
  checkMime(operation, path) {
    if (this.rules.allowedMimeTypes.length > 0) {
      var mime = mimeOf(path);
      if (this.rules.allowedMimeTypes.indexOf(mime) === -1) {
        policyError(operation, "allowedMimeTypes", "mime type not allowed: '" + path + "' (" + mime + ")");
      }
    }
  }

  /**
   * Full read guard: hidden, then extension + MIME (dirs exempt).
   * @param {string} operation - Operation name.
   * @param {string} path - Path to check.
   * @returns {void} Throws on violation.
   */
  checkAccess(operation, path) {
    this.checkHidden(operation, path);
    if (this.isDirPath(path)) return;
    this.checkExtension(operation, path);
    this.checkMime(operation, path);
  }

  /**
   * Filter variant of checkAccess for list/search results.
   * @param {string} path - Path to test.
   * @param {boolean} isDir - Whether the entry is a directory.
   * @returns {boolean} True when the entry passes the rules.
   */
  pathAllowed(path, isDir) {
    if (this.rules.denyHiddenFiles && this.isHidden(path)) return false;
    if (isDir) return true;
    if (this.rules.allowedExtensions.length > 0) {
      var ext = extOf(path);
      var allowed = this.rules.allowedExtensions.map(function (e) { return String(e).toLowerCase(); });
      if (ext === "" || allowed.indexOf(ext) === -1) return false;
    }
    if (this.rules.allowedMimeTypes.length > 0) {
      if (this.rules.allowedMimeTypes.indexOf(mimeOf(path)) === -1) return false;
    }
    return true;
  }

  /**
   * Enforces the max file size.
   * @param {string} operation - Operation name.
   * @param {number} size - Size in bytes.
   * @returns {void} Throws on violation.
   */
  checkSize(operation, size) {
    if (this.rules.maxFileSize > 0 && size > this.rules.maxFileSize) {
      policyError(operation, "maxFileSize", size + " bytes exceeds limit of " + this.rules.maxFileSize);
    }
  }

  /**
   * Pre-checks every file a directory copy/move would create.
   * @param {string} operation - Operation name.
   * @param {string} src - Source directory.
   * @param {string} dest - Destination directory.
   * @returns {void} Throws on violation.
   */
  checkTree(operation, src, dest) {
    var items = this.inner.list(src, true);
    for (var i = 0; i < items.length; i++) {
      if (items[i].isDir) continue;
      var rel = items[i].path;
      if (src.length > 0 && rel.indexOf(src + "/") === 0) rel = rel.slice(src.length + 1);
      else if (src.length === 0) rel = items[i].path;
      var destPath = dest === "" ? rel : dest + "/" + rel;
      this.checkPath(operation, destPath);
      this.checkAccess(operation, destPath);
    }
  }

  /**
   * Reads a file as text.
   * @param {string} path - File path.
   * @returns {string} File content.
   */
  read(path) {
    this.checkPath("read", path);
    this.checkAccess("read", path);
    this.checkSize("read", this.inner.size(path));
    return this.inner.read(path);
  }

  /**
   * Reads a file as bytes.
   * @param {string} path - File path.
   * @returns {Uint8Array} File content.
   */
  readBytes(path) {
    this.checkPath("read", path);
    this.checkAccess("read", path);
    this.checkSize("read", this.inner.size(path));
    return this.inner.readBytes(path);
  }

  /**
   * Checks existence.
   * @param {string} path - Path to check.
   * @returns {boolean} True when present.
   */
  exists(path) {
    this.checkPath("exists", path);
    return this.inner.exists(path);
  }

  /**
   * Lists a directory, filtered by policy.
   * @param {string} path - Directory path.
   * @param {boolean} [recursive] - Recurse into subdirectories.
   * @returns {Array} Visible entries.
   */
  list(path, recursive) {
    this.checkPath("list", path);
    var out = [];
    var items = this.inner.list(path, recursive);
    for (var i = 0; i < items.length; i++) {
      if (this.pathAllowed(items[i].path, items[i].isDir)) out.push(items[i]);
    }
    return out;
  }

  /**
   * Searches files by glob, filtered by policy.
   * @param {string} pattern - Glob pattern.
   * @returns {string[]} Matching paths.
   */
  search(pattern) {
    this.checkPath("search", pattern);
    var out = [];
    var hits = this.inner.search(pattern);
    for (var j = 0; j < hits.length; j++) {
      if (this.pathAllowed(hits[j], false)) out.push(hits[j]);
    }
    return out;
  }

  /**
   * Returns file visibility.
   * @param {string} path - File path.
   * @returns {string} "public" or "private".
   */
  visibility(path) {
    this.checkPath("visibility", path);
    this.checkAccess("visibility", path);
    return this.inner.visibility(path);
  }

  /**
   * Returns file metadata.
   * @param {string} path - Path to inspect.
   * @returns {object} Metadata object.
   */
  metadata(path) {
    this.checkPath("metadata", path);
    this.checkAccess("metadata", path);
    return this.inner.metadata(path);
  }

  /**
   * Returns file size in bytes.
   * @param {string} path - File path.
   * @returns {number} Size in bytes.
   */
  size(path) {
    this.checkPath("size", path);
    this.checkAccess("size", path);
    return this.inner.size(path);
  }

  /**
   * Returns last-modified timestamp.
   * @param {string} path - File path.
   * @returns {number} Millisecond timestamp.
   */
  lastModified(path) {
    this.checkPath("lastModified", path);
    this.checkAccess("lastModified", path);
    return this.inner.lastModified(path);
  }

  /**
   * Returns the file checksum.
   * @param {string} path - File path.
   * @returns {string} Checksum string.
   */
  checksum(path) {
    this.checkPath("checksum", path);
    this.checkAccess("checksum", path);
    return this.inner.checksum(path);
  }

  /**
   * Returns the MIME type.
   * @param {string} path - File path.
   * @returns {string} MIME type.
   */
  mimeType(path) {
    this.checkPath("mimeType", path);
    this.checkAccess("mimeType", path);
    return this.inner.mimeType(path);
  }

  /**
   * Reads a file split into lines.
   * @param {string} path - File path.
   * @returns {string[]} Lines.
   */
  readLines(path) {
    this.checkPath("read", path);
    this.checkAccess("read", path);
    this.checkSize("read", this.inner.size(path));
    return this.inner.readLines(path);
  }

  /**
   * Writes content atomically via the inner driver.
   * @param {string} path - File path.
   * @param {string|Uint8Array} content - Content to write.
   * @param {string} [visibility] - "public" or "private".
   * @returns {void}
   */
  write(path, content, visibility) {
    this.checkWritable("write");
    this.checkPath("write", path);
    this.checkAccess("write", path);
    var s = typeof content === "string" ? content.length : content.length;
    this.checkSize("write", s);
    return this.inner.write(path, content, visibility);
  }

  /**
   * Appends content to a file.
   * @param {string} path - File path.
   * @param {string} content - Content to append.
   * @returns {void}
   */
  append(path, content) {
    this.checkWritable("append");
    this.checkPath("append", path);
    this.checkAccess("append", path);
    var existing = this.inner.exists(path) ? this.inner.size(path) : 0;
    this.checkSize("append", existing + String(content).length);
    return this.inner.append(path, content);
  }

  /**
   * Deletes a file.
   * @param {string} path - File path.
   * @returns {void}
   */
  delete(path) {
    this.checkWritable("delete");
    this.checkPath("delete", path);
    return this.inner.delete(path);
  }

  /**
   * Moves a file.
   * @param {string} src - Source path.
   * @param {string} dest - Destination path.
   * @returns {void}
   */
  move(src, dest) {
    this.checkWritable("move");
    this.checkPath("move", src);
    this.checkPath("move", dest);
    this.checkAccess("move", dest);
    return this.inner.move(src, dest);
  }

  /**
   * Copies a file.
   * @param {string} src - Source path.
   * @param {string} dest - Destination path.
   * @returns {void}
   */
  copy(src, dest) {
    this.checkWritable("copy");
    this.checkPath("copy", src);
    this.checkPath("copy", dest);
    this.checkAccess("copy", dest);
    return this.inner.copy(src, dest);
  }

  /**
   * Creates a directory.
   * @param {string} path - Directory path.
   * @returns {void}
   */
  makeDir(path) {
    this.checkWritable("makeDir");
    this.checkPath("makeDir", path);
    this.checkHidden("makeDir", path);
    return this.inner.makeDir(path);
  }

  /**
   * Deletes a directory.
   * @param {string} path - Directory path.
   * @param {boolean} [force] - Remove non-empty trees.
   * @returns {void}
   */
  deleteDir(path, force) {
    this.checkWritable("deleteDir");
    this.checkPath("deleteDir", path);
    return this.inner.deleteDir(path, force);
  }

  /**
   * Creates an empty file when missing.
   * @param {string} path - File path.
   * @returns {void}
   */
  touch(path) {
    this.checkWritable("touch");
    this.checkPath("touch", path);
    this.checkAccess("touch", path);
    return this.inner.touch(path);
  }

  /**
   * Copies a directory tree.
   * @param {string} src - Source directory.
   * @param {string} dest - Destination directory.
   * @returns {void}
   */
  copyDir(src, dest) {
    this.checkWritable("copyDir");
    this.checkPath("copyDir", src);
    this.checkPath("copyDir", dest);
    this.checkHidden("copyDir", dest);
    this.checkTree("copyDir", src, dest);
    return this.inner.copyDir(src, dest);
  }

  /**
   * Moves a directory tree.
   * @param {string} src - Source directory.
   * @param {string} dest - Destination directory.
   * @returns {void}
   */
  moveDir(src, dest) {
    this.checkWritable("moveDir");
    this.checkPath("moveDir", src);
    this.checkPath("moveDir", dest);
    this.checkHidden("moveDir", dest);
    this.checkTree("moveDir", src, dest);
    return this.inner.moveDir(src, dest);
  }

  /**
   * Sets file visibility.
   * @param {string} path - File path.
   * @param {string} v - "public" or "private".
   * @returns {void}
   */
  setVisibility(path, v) {
    this.checkWritable("setVisibility");
    this.checkPath("setVisibility", path);
    return this.inner.setVisibility(path, v);
  }

  /**
   * Creates a symlink inside the sandbox.
   * @param {string} path - Link path.
   * @param {string} target - Target path.
   * @returns {void}
   */
  createSymlink(path, target) {
    this.checkWritable("createSymlink");
    this.checkPath("createSymlink", path);
    this.checkPath("createSymlink", target);
    this.checkAccess("createSymlink", target);
    return this.inner.createSymlink(path, target);
  }

  /**
   * Checks whether a path is a symlink.
   * @param {string} path - Path to check.
   * @returns {boolean} True when a symlink.
   */
  isSymlink(path) {
    this.checkPath("isSymlink", path);
    return this.inner.isSymlink(path);
  }

  /**
   * Reads a symlink target.
   * @param {string} path - Link path.
   * @returns {string} Target path.
   */
  readLink(path) {
    this.checkPath("readLink", path);
    this.checkAccess("readLink", path);
    return this.inner.readLink(path);
  }
}

/**
 * Creates a policy wrapper around a driver.
 * @param {object} inner - Inner driver to guard.
 * @param {object} [rules] - Partial policy rules.
 * @returns {FilesystemPolicy} Guarded driver.
 */
function newFilesystemPolicy(inner, rules) {
  return new FilesystemPolicy(inner, rules);
}

module.exports = { FilesystemPolicy, newFilesystemPolicy, defaultPolicyRules };
