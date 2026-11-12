// flysystem policy: FilesystemPolicy wraps any driver and enforces
// PolicyRules. Port of Nim policy.nim (read-only, size caps, path
// limits, hidden-file denial, extension/MIME allowlists).

const mimetype = require("std/mimetype");
const { StorageError, FilesystemPolicyError } = require("./errors.js");

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

function basename(p) {
  var idx = p.lastIndexOf("/");
  return idx === -1 ? p : p.slice(idx + 1);
}

function extOf(path) {
  var base = basename(path);
  var dot = base.lastIndexOf(".");
  if (dot === -1) return "";
  return base.slice(dot + 1).toLowerCase();
}

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

function policyError(operation, rule, detail) {
  throw new FilesystemPolicyError(operation, rule, detail);
}

class FilesystemPolicy {
  constructor(inner, rules) {
    if (!inner) throw new StorageError("FilesystemPolicy requires an inner driver");
    this.inner = inner;
    this.rules = Object.assign(defaultPolicyRules(), rules || {});
  }

  checkWritable(operation) {
    if (this.rules.readOnly) policyError(operation, "readOnly", "is not allowed in read-only mode");
  }

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

  isHidden(path) {
    var name = basename(path);
    return name.length > 0 && name[0] === ".";
  }

  checkHidden(operation, path) {
    if (this.rules.denyHiddenFiles && this.isHidden(path)) {
      policyError(operation, "denyHiddenFiles", "hidden path: '" + path + "'");
    }
  }

  isDirPath(path) {
    try {
      return this.inner.metadata(path).isDir;
    } catch (_) {
      return false;
    }
  }

  checkExtension(operation, path) {
    if (this.rules.allowedExtensions.length > 0) {
      var ext = extOf(path);
      var allowed = this.rules.allowedExtensions.map(function (e) { return String(e).toLowerCase(); });
      if (ext === "" || allowed.indexOf(ext) === -1) {
        policyError(operation, "allowedExtensions", "extension not allowed: '" + path + "'");
      }
    }
  }

  checkMime(operation, path) {
    if (this.rules.allowedMimeTypes.length > 0) {
      var mime = mimeOf(path);
      if (this.rules.allowedMimeTypes.indexOf(mime) === -1) {
        policyError(operation, "allowedMimeTypes", "mime type not allowed: '" + path + "' (" + mime + ")");
      }
    }
  }

  checkAccess(operation, path) {
    this.checkHidden(operation, path);
    if (this.isDirPath(path)) return;
    this.checkExtension(operation, path);
    this.checkMime(operation, path);
  }

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

  checkSize(operation, size) {
    if (this.rules.maxFileSize > 0 && size > this.rules.maxFileSize) {
      policyError(operation, "maxFileSize", size + " bytes exceeds limit of " + this.rules.maxFileSize);
    }
  }

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

  // reads
  read(path) { this.checkPath("read", path); this.checkAccess("read", path); this.checkSize("read", this.inner.size(path)); return this.inner.read(path); }
  readBytes(path) { this.checkPath("read", path); this.checkAccess("read", path); this.checkSize("read", this.inner.size(path)); return this.inner.readBytes(path); }
  exists(path) { this.checkPath("exists", path); return this.inner.exists(path); }
  list(path, recursive) { this.checkPath("list", path); var out = []; var items = this.inner.list(path, recursive); for (var i = 0; i < items.length; i++) if (this.pathAllowed(items[i].path, items[i].isDir)) out.push(items[i]); return out; }
  search(pattern) { this.checkPath("search", pattern); var out = []; var hits = this.inner.search(pattern); for (var j = 0; j < hits.length; j++) if (this.pathAllowed(hits[j], false)) out.push(hits[j]); return out; }
  visibility(path) { this.checkPath("visibility", path); this.checkAccess("visibility", path); return this.inner.visibility(path); }
  metadata(path) { this.checkPath("metadata", path); this.checkAccess("metadata", path); return this.inner.metadata(path); }
  size(path) { this.checkPath("size", path); this.checkAccess("size", path); return this.inner.size(path); }
  lastModified(path) { this.checkPath("lastModified", path); this.checkAccess("lastModified", path); return this.inner.lastModified(path); }
  checksum(path) { this.checkPath("checksum", path); this.checkAccess("checksum", path); return this.inner.checksum(path); }
  mimeType(path) { this.checkPath("mimeType", path); this.checkAccess("mimeType", path); return this.inner.mimeType(path); }
  readLines(path) { this.checkPath("read", path); this.checkAccess("read", path); this.checkSize("read", this.inner.size(path)); return this.inner.readLines(path); }

  // writes
  write(path, content, visibility) { this.checkWritable("write"); this.checkPath("write", path); this.checkAccess("write", path); var s = typeof content === "string" ? content.length : content.length; this.checkSize("write", s); return this.inner.write(path, content, visibility); }
  append(path, content) { this.checkWritable("append"); this.checkPath("append", path); this.checkAccess("append", path); var existing = this.inner.exists(path) ? this.inner.size(path) : 0; this.checkSize("append", existing + String(content).length); return this.inner.append(path, content); }
  delete(path) { this.checkWritable("delete"); this.checkPath("delete", path); return this.inner.delete(path); }
  move(src, dest) { this.checkWritable("move"); this.checkPath("move", src); this.checkPath("move", dest); this.checkAccess("move", dest); return this.inner.move(src, dest); }
  copy(src, dest) { this.checkWritable("copy"); this.checkPath("copy", src); this.checkPath("copy", dest); this.checkAccess("copy", dest); return this.inner.copy(src, dest); }
  makeDir(path) { this.checkWritable("makeDir"); this.checkPath("makeDir", path); this.checkHidden("makeDir", path); return this.inner.makeDir(path); }
  deleteDir(path, force) { this.checkWritable("deleteDir"); this.checkPath("deleteDir", path); return this.inner.deleteDir(path, force); }
  touch(path) { this.checkWritable("touch"); this.checkPath("touch", path); this.checkAccess("touch", path); return this.inner.touch(path); }
  copyDir(src, dest) { this.checkWritable("copyDir"); this.checkPath("copyDir", src); this.checkPath("copyDir", dest); this.checkHidden("copyDir", dest); this.checkTree("copyDir", src, dest); return this.inner.copyDir(src, dest); }
  moveDir(src, dest) { this.checkWritable("moveDir"); this.checkPath("moveDir", src); this.checkPath("moveDir", dest); this.checkHidden("moveDir", dest); this.checkTree("moveDir", src, dest); return this.inner.moveDir(src, dest); }
  setVisibility(path, v) { this.checkWritable("setVisibility"); this.checkPath("setVisibility", path); return this.inner.setVisibility(path, v); }
  createSymlink(path, target) { this.checkWritable("createSymlink"); this.checkPath("createSymlink", path); this.checkPath("createSymlink", target); this.checkAccess("createSymlink", target); return this.inner.createSymlink(path, target); }
  isSymlink(path) { this.checkPath("isSymlink", path); return this.inner.isSymlink(path); }
  readLink(path) { this.checkPath("readLink", path); this.checkAccess("readLink", path); return this.inner.readLink(path); }
}

function newFilesystemPolicy(inner, rules) {
  return new FilesystemPolicy(inner, rules);
}

module.exports = { FilesystemPolicy, newFilesystemPolicy, defaultPolicyRules };
