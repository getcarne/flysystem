// flysystem LocalDriver: sandboxed local filesystem, OOP port of Nim
// local_lexical_impl.nim (lexical containment, atomic tmp+rename writes).
//
// Only std/os + std/env + std/crypto + std/mimetype are used, so this
// runs on any Carne release with chmod/mode + hash.md5 support.
//
// Visibility maps to Unix modes like Nim: public = 0o644, private = 0o600,
// and visibility() checks the others-read bit.

const os = require("std/os");
const env = require("std/env");
const crypto = require("std/crypto");
const mimetype = require("std/mimetype");
const { StorageError } = require("./errors.js");

const VIS_PUBLIC = "public";
const VIS_PRIVATE = "private";

var tmpCounter = 0;

function isAbsolute(p) {
  return p.length > 0 && p[0] === "/";
}

function normalizePath(p) {
  var absolute = isAbsolute(p);
  var parts = p.split("/");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var seg = parts[i];
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0) out.pop();
      else if (!absolute) out.push("..");
      // absolute ".." above root collapses to root
    } else {
      out.push(seg);
    }
  }
  var res = (absolute ? "/" : "") + out.join("/");
  if (res === "") return absolute ? "/" : ".";
  return res;
}

function joinPath(a, b) {
  if (b.length === 0) return a;
  if (isAbsolute(b)) return normalizePath(b);
  if (a === "/") return normalizePath("/" + b);
  return normalizePath(a + "/" + b);
}

function basename(p) {
  var n = normalizePath(p);
  if (n === "/") return "/";
  var idx = n.lastIndexOf("/");
  return idx === -1 ? n : n.slice(idx + 1);
}

function dirname(p) {
  var n = normalizePath(p);
  if (n === "/" || n.indexOf("/") === -1) return ".";
  var idx = n.lastIndexOf("/");
  if (idx === 0) return "/";
  return n.slice(0, idx);
}

function parentDir(full) {
  var idx = full.lastIndexOf("/");
  if (idx <= 0) return idx === 0 ? "/" : ".";
  return full.slice(0, idx);
}

function globToRegExp(glob) {
  var re = "^";
  for (var i = 0; i < glob.length; i++) {
    var c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // ** matches across separators
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i++;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if ("\\.+()|^$[]{}|".indexOf(c) !== -1) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp(re + "$");
}

class LocalDriver {
  constructor(root) {
    if (typeof root !== "string" || root.length === 0) {
      throw new StorageError("LocalDriver requires a non-empty root path");
    }
    var abs = isAbsolute(root) ? normalizePath(root) : joinPath(env.cwd(), root);
    this.root = abs;
    try {
      if (!os.exists(abs)) {
        os.mkdir(abs, true);
      }
    } catch (e) {
      throw new StorageError("Failed to create root '" + abs + "': " + e.message);
    }
    this.sroot = abs;
  }

  resolvePath(path) {
    if (typeof path !== "string") {
      throw new StorageError("Path must be a string");
    }
    if (path.length === 0) return this.root;
    var resolved = isAbsolute(path) ? normalizePath(path) : joinPath(this.root, path);
    if (resolved !== this.root && resolved.indexOf(this.root + "/") !== 0) {
      throw new StorageError("Path traversal detected: " + path);
    }
    return resolved;
  }

  relPath(full) {
    if (full === this.root) return "";
    return full.slice(this.root.length + 1);
  }

  ensureParent(full) {
    var dir = parentDir(full);
    if (dir === "." || dir === "/" || dir === this.root) {
      if (!os.exists(this.root)) os.mkdir(this.root, true);
      if (dir !== "." && dir !== "/" && !os.exists(dir)) os.mkdir(dir, true);
      return;
    }
    if (!os.exists(dir)) os.mkdir(dir, true);
  }

  tempPath(full) {
    tmpCounter += 1;
    return full + ".tmp." + os.pid() + "." + tmpCounter;
  }

  atomicWrite(full, writeFn, visibility) {
    this.ensureParent(full);
    var tmp = this.tempPath(full);
    try {
      writeFn(tmp);
    } catch (e) {
      try { if (os.exists(tmp)) os.remove(tmp); } catch (_) {}
      throw new StorageError("Failed to write '" + this.relPath(full) + "': " + e.message);
    }
    try {
      if (visibility === VIS_PUBLIC) os.chmod(tmp, 420); // 0o644
      else if (visibility === VIS_PRIVATE) os.chmod(tmp, 384); // 0o600
    } catch (e) {
      try { if (os.exists(tmp)) os.remove(tmp); } catch (_) {}
      throw new StorageError("Failed to write '" + this.relPath(full) + "': " + e.message);
    }
    try {
      os.move(tmp, full);
    } catch (e) {
      try { if (os.exists(tmp)) os.remove(tmp); } catch (_) {}
      throw new StorageError("Failed to write '" + this.relPath(full) + "': " + e.message);
    }
  }

  write(path, content, visibility) {
    if (visibility === undefined) visibility = VIS_PRIVATE;
    var full = this.resolvePath(path);
    var self = this;
    this.atomicWrite(full, function (tmp) {
      if (content instanceof Uint8Array) os.writeFileBytes(tmp, content);
      else os.writeFile(tmp, String(content));
    }, visibility);
    void self;
  }

  read(path) {
    var full = this.resolvePath(path);
    try {
      return os.readFile(full);
    } catch (e) {
      throw new StorageError("Failed to read '" + path + "': " + e.message);
    }
  }

  readBytes(path) {
    var full = this.resolvePath(path);
    try {
      return os.readFileBytes(full);
    } catch (e) {
      throw new StorageError("Failed to read '" + path + "': " + e.message);
    }
  }

  append(path, content) {
    var full = this.resolvePath(path);
    try {
      if (!os.exists(full)) this.ensureParent(full);
      os.appendFile(full, String(content));
    } catch (e) {
      throw new StorageError("Failed to append to '" + path + "': " + e.message);
    }
  }

  delete(path) {
    var full = this.resolvePath(path);
    try {
      os.remove(full);
      return;
    } catch (_) {}
    try {
      os.removeDir(full);
    } catch (e) {
      throw new StorageError("Failed to delete '" + path + "': " + e.message);
    }
  }

  createSymlink(path, target) {
    var link = this.resolvePath(path);
    var dest = this.resolvePath(target);
    try {
      this.ensureParent(link);
      os.symlink(dest, link);
    } catch (e) {
      if (e instanceof StorageError) throw e;
      throw new StorageError("Failed to create symlink '" + path + "' -> '" + target + "': " + e.message);
    }
  }

  isSymlink(path) {
    var full = this.resolvePath(path);
    try {
      return os.isSymlink(full);
    } catch (e) {
      throw new StorageError("Failed to check symlink '" + path + "': " + e.message);
    }
  }

  readLink(path) {
    var full = this.resolvePath(path);
    try {
      var target = os.readLink(full);
      if (target === this.root) return "";
      if (target.indexOf(this.root + "/") === 0) return target.slice(this.root.length + 1);
      throw new StorageError("Path traversal detected: " + path);
    } catch (e) {
      if (e instanceof StorageError) throw e;
      throw new StorageError("Failed to read symlink '" + path + "': " + e.message);
    }
  }

  exists(path) {
    var full = this.resolvePath(path);
    try {
      return os.exists(full);
    } catch (e) {
      throw new StorageError("Failed to check existence of '" + path + "': " + e.message);
    }
  }

  list(path, recursive) {
    if (path === undefined) path = "";
    if (recursive === undefined) recursive = false;
    var full = this.resolvePath(path);
    var out = [];
    var self = this;
    try {
      if (!recursive) {
        var entries = os.readDir(full === "" ? this.root : full);
        for (var i = 0; i < entries.length; i++) {
          var e = entries[i];
          var childFull = full === "/" ? "/" + e.name : full + "/" + e.name;
          var st = os.stat(childFull);
          out.push({
            path: self.relPath(childFull),
            size: e.kind === "file" ? st.size : 0,
            lastModified: st.mtimeMs,
            isDir: e.kind === "dir",
          });
        }
      } else {
        var stack = [full];
        while (stack.length > 0) {
          var dir = stack.pop();
          var items = os.readDir(dir);
          for (var j = 0; j < items.length; j++) {
            var it = items[j];
            var cf = dir === "/" ? "/" + it.name : dir + "/" + it.name;
            var s = os.stat(cf);
            var isDir = it.kind === "dir";
            out.push({
              path: self.relPath(cf),
              size: isDir ? 0 : s.size,
              lastModified: s.mtimeMs,
              isDir: isDir,
            });
            if (isDir) stack.push(cf);
          }
        }
      }
    } catch (e) {
      if (e instanceof StorageError) throw e;
      throw new StorageError("Failed to list '" + path + "': " + e.message);
    }
    return out;
  }

  move(src, dest) {
    var srcFull = this.resolvePath(src);
    var destFull = this.resolvePath(dest);
    try {
      this.ensureParent(destFull);
      os.move(srcFull, destFull);
    } catch (e) {
      throw new StorageError("Failed to move '" + src + "' to '" + dest + "': " + e.message);
    }
  }

  copy(src, dest) {
    var srcFull = this.resolvePath(src);
    var destFull = this.resolvePath(dest);
    try {
      this.ensureParent(destFull);
      os.copy(srcFull, destFull);
    } catch (e) {
      throw new StorageError("Failed to copy '" + src + "' to '" + dest + "': " + e.message);
    }
  }

  makeDir(path) {
    var full = this.resolvePath(path);
    try {
      if (!os.exists(full)) os.mkdir(full, true);
    } catch (e) {
      throw new StorageError("Failed to create directory '" + path + "': " + e.message);
    }
  }

  deleteDir(path, force) {
    if (force === undefined) force = false;
    var full = this.resolvePath(path);
    try {
      if (force) {
        os.removeDir(full, true);
        return;
      }
      if (!os.exists(full)) return;
      var items = os.readDir(full);
      if (items.length > 0) {
        throw new StorageError("Directory not empty: " + path);
      }
      os.removeDir(full);
    } catch (e) {
      if (e instanceof StorageError) throw e;
      throw new StorageError("Failed to delete directory '" + path + "': " + e.message);
    }
  }

  touch(path) {
    var full = this.resolvePath(path);
    try {
      this.ensureParent(full);
      if (!os.exists(full)) os.writeFile(full, "");
      else os.appendFile(full, "");
    } catch (e) {
      throw new StorageError("Failed to touch '" + path + "': " + e.message);
    }
  }

  copyDir(src, dest) {
    var srcFull = this.resolvePath(src);
    var destFull = this.resolvePath(dest);
    try {
      if (!os.exists(destFull)) os.mkdir(destFull, true);
      var entries = os.readDir(srcFull);
      for (var i = 0; i < entries.length; i++) {
        var name = entries[i].name;
        var sFull = srcFull + "/" + name;
        var dFull = destFull + "/" + name;
        var rel = this.relPath(sFull);
        var destRel = this.relPath(dFull);
        if (os.isDir(sFull)) this.copyDir(rel, destRel);
        else if (os.isFile(sFull)) {
          this.ensureParent(dFull);
          os.copy(sFull, dFull);
        }
      }
    } catch (e) {
      if (e instanceof StorageError) throw e;
      throw new StorageError("Failed to copy directory '" + src + "' to '" + dest + "': " + e.message);
    }
  }

  moveDir(src, dest) {
    var srcFull = this.resolvePath(src);
    var destFull = this.resolvePath(dest);
    try {
      this.ensureParent(destFull);
      os.move(srcFull, destFull);
    } catch (e) {
      throw new StorageError("Failed to move directory '" + src + "' to '" + dest + "': " + e.message);
    }
  }

  search(pattern) {
    if (typeof pattern !== "string") {
      throw new StorageError("Failed to search '" + pattern + "': pattern must be a string");
    }
    if (pattern.indexOf("..") !== -1) {
      var segs = pattern.split("/");
      for (var i = 0; i < segs.length; i++) {
        if (segs[i] === "..") throw new StorageError("Path traversal detected: " + pattern);
      }
    }
    var re = globToRegExp(pattern);
    var all = this.list("", true);
    var filesOnly = [];
    for (var k = 0; k < all.length; k++) {
      if (!all[k].isDir && re.test(all[k].path)) filesOnly.push(all[k].path);
    }
    // non-recursive patterns like "*.txt" must not match nested paths:
    // the regex already enforces separator boundaries via [^/]*.
    filesOnly.sort();
    return filesOnly;
  }

  setVisibility(path, visibility) {
    var full = this.resolvePath(path);
    try {
      if (visibility === VIS_PUBLIC) os.chmod(full, 420);
      else os.chmod(full, 384);
    } catch (e) {
      throw new StorageError("Failed to set visibility of '" + path + "': " + e.message);
    }
  }

  visibility(path) {
    var full = this.resolvePath(path);
    try {
      var mode = os.stat(full).mode;
      return (mode & 4) !== 0 ? VIS_PUBLIC : VIS_PRIVATE;
    } catch (e) {
      throw new StorageError("Failed to get visibility of '" + path + "': " + e.message);
    }
  }

  metadata(path) {
    var full = this.resolvePath(path);
    try {
      var st = os.stat(full);
      return {
        path: this.relPath(full).split("\\").join("/"),
        size: st.size,
        lastModified: st.mtimeMs,
        isDir: st.kind === "dir",
      };
    } catch (e) {
      throw new StorageError("Failed to retrieve metadata of '" + path + "': " + e.message);
    }
  }

  size(path) {
    return this.metadata(path).size;
  }

  lastModified(path) {
    return this.metadata(path).lastModified;
  }

  checksum(path) {
    var content = this.read(path);
    try {
      return crypto.hash.md5(content);
    } catch (e) {
      throw new StorageError("Failed to checksum '" + path + "': " + e.message);
    }
  }

  mimeType(path) {
    var base = basename(path);
    var dot = base.lastIndexOf(".");
    if (dot === -1 || dot === base.length - 1) return "application/octet-stream";
    var ext = base.slice(dot + 1);
    try {
      var t = mimetype.lookup(ext);
      return t === null || t === undefined ? "application/octet-stream" : t;
    } catch (_) {
      return "application/octet-stream";
    }
  }

  readLines(path) {
    var content = this.read(path);
    if (content.length === 0) return [];
    var parts = content.split("\n");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
      var line = parts[i];
      if (line.length > 0 && line[line.length - 1] === "\r") line = line.slice(0, -1);
      // drop trailing empty from final newline
      if (i === parts.length - 1 && line === "") break;
      out.push(line);
    }
    return out;
  }
}

function newLocalDriver(root) {
  return new LocalDriver(root);
}

module.exports = { LocalDriver, newLocalDriver, VIS_PUBLIC, VIS_PRIVATE };
