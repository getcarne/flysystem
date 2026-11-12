// flysystem LocalDriver: sandboxed local filesystem, OOP port of Nim
// local_lexical_impl.nim (lexical containment, atomic tmp+rename writes).
//
// Only std/os + std/env + std/crypto + std/mimetype are used, so this
// runs on any Carne release with chmod/mode + hash.md5 support.
//
// Visibility maps to Unix modes like Nim: public = 0o644, private = 0o600,
// and visibility() checks the others-read bit.
//
// In plain terms: you point the driver at one folder (the "root") and
// every path you pass stays inside it. Writes go to a temp file first
// and are then renamed, so a crash never leaves a half-written file.

const os = require("std/os");
const env = require("std/env");
const crypto = require("std/crypto");
const mimetype = require("std/mimetype");
const { StorageError } = require("./errors.js");

/** Public files: readable by everyone (`0o644`). */
const VIS_PUBLIC = "public";
/** Private files: owner-only (`0o600`). This is the default. */
const VIS_PRIVATE = "private";

var tmpCounter = 0;

/**
 * True when a path starts at the filesystem root.
 * @param {string} p - Path to test.
 * @returns {boolean} True for "/..." paths.
 */
function isAbsolute(p) {
  return p.length > 0 && p[0] === "/";
}

/**
 * Cleans up `.`, doubles slashes and `..` without touching disk.
 * Absolute `..` above root just stays at root.
 * @param {string} p - Raw path.
 * @returns {string} Cleaned path.
 */
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

/**
 * Joins two path pieces and cleans the result.
 * An absolute second piece wins outright.
 * @param {string} a - Base path.
 * @param {string} b - Piece to append.
 * @returns {string} Joined, normalized path.
 */
function joinPath(a, b) {
  if (b.length === 0) return a;
  if (isAbsolute(b)) return normalizePath(b);
  if (a === "/") return normalizePath("/" + b);
  return normalizePath(a + "/" + b);
}

/**
 * Last segment of a path.
 * @param {string} p - Path to split.
 * @returns {string} File or folder name.
 */
function basename(p) {
  var n = normalizePath(p);
  if (n === "/") return "/";
  var idx = n.lastIndexOf("/");
  return idx === -1 ? n : n.slice(idx + 1);
}

/**
 * Everything before the last segment.
 * @param {string} p - Path to split.
 * @returns {string} Parent path.
 */
function dirname(p) {
  var n = normalizePath(p);
  if (n === "/" || n.indexOf("/") === -1) return ".";
  var idx = n.lastIndexOf("/");
  if (idx === 0) return "/";
  return n.slice(0, idx);
}

/**
 * Parent of an already-resolved absolute path.
 * @param {string} full - Full path on disk.
 * @returns {string} Parent directory.
 */
function parentDir(full) {
  var idx = full.lastIndexOf("/");
  if (idx <= 0) return idx === 0 ? "/" : ".";
  return full.slice(0, idx);
}

/**
 * Turns a glob like `*.txt` or `** / *.js` into a RegExp.
 * `*` stays inside one folder, `**` crosses folders, `?` is one char.
 * @param {string} glob - Glob pattern.
 * @returns {RegExp} Matching expression.
 */
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

/**
 * One sandboxed folder on disk. Every path you pass is kept inside
 * the root; anything trying to escape throws StorageError.
 */
class LocalDriver {
  /**
   * Points the driver at a folder, creating it when missing.
   * Relative roots resolve from the current working directory.
   * @param {string} root - Folder to sandbox into.
   */
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

  /**
   * Resolves a user path to a real path, blocking escapes.
   * Empty string means the root itself.
   * @param {string} path - User-supplied path.
   * @returns {string} Absolute path guaranteed inside the root.
   */
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

  /**
   * Turns a real path back into a root-relative one.
   * @param {string} full - Absolute path inside the root.
   * @returns {string} Path relative to the root ("" for root).
   */
  relPath(full) {
    if (full === this.root) return "";
    return full.slice(this.root.length + 1);
  }

  /**
   * Creates the parent folder chain for a file.
   * @param {string} full - Absolute file path.
   * @returns {void}
   */
  ensureParent(full) {
    var dir = parentDir(full);
    if (dir === "." || dir === "/" || dir === this.root) {
      if (!os.exists(this.root)) os.mkdir(this.root, true);
      if (dir !== "." && dir !== "/" && !os.exists(dir)) os.mkdir(dir, true);
      return;
    }
    if (!os.exists(dir)) os.mkdir(dir, true);
  }

  /**
   * Unique temp path next to the destination for atomic writes.
   * @param {string} full - Final destination path.
   * @returns {string} Temp path to write first.
   */
  tempPath(full) {
    tmpCounter += 1;
    return full + ".tmp." + os.pid() + "." + tmpCounter;
  }

  /**
   * Writes via a temp file, sets permissions, then renames over.
   * Readers never see a half-written file. Cleans up on failure.
   * @param {string} full - Absolute destination path.
   * @param {Function} writeFn - Called with the temp path to fill.
   * @param {string} visibility - "public" or "private".
   * @returns {void}
   */
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

  /**
   * Writes text or bytes, creating parents as needed.
   * Defaults to private when no visibility is given.
   * @param {string} path - Destination path.
   * @param {string|Uint8Array} content - Text or raw bytes.
   * @param {string} [visibility] - "public" or "private".
   * @returns {void}
   */
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

  /**
   * Reads a file as text.
   * @param {string} path - File path.
   * @returns {string} File content.
   */
  read(path) {
    var full = this.resolvePath(path);
    try {
      return os.readFile(full);
    } catch (e) {
      throw new StorageError("Failed to read '" + path + "': " + e.message);
    }
  }

  /**
   * Reads a file as raw bytes (images, zips, anything binary).
   * @param {string} path - File path.
   * @returns {Uint8Array} File bytes.
   */
  readBytes(path) {
    var full = this.resolvePath(path);
    try {
      return os.readFileBytes(full);
    } catch (e) {
      throw new StorageError("Failed to read '" + path + "': " + e.message);
    }
  }

  /**
   * Adds text to the end of a file, creating it when missing.
   * @param {string} path - File path.
   * @param {string} content - Text to append.
   * @returns {void}
   */
  append(path, content) {
    var full = this.resolvePath(path);
    try {
      if (!os.exists(full)) this.ensureParent(full);
      os.appendFile(full, String(content));
    } catch (e) {
      throw new StorageError("Failed to append to '" + path + "': " + e.message);
    }
  }

  /**
   * Deletes a file (or an empty folder as fallback).
   * @param {string} path - Path to remove.
   * @returns {void}
   */
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

  /**
   * Creates a symlink. Both ends must stay inside the root.
   * @param {string} path - Where the link goes.
   * @param {string} target - What the link points to.
   * @returns {void}
   */
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

  /**
   * Checks whether a path is a symlink.
   * @param {string} path - Path to check.
   * @returns {boolean} True when it is a link.
   */
  isSymlink(path) {
    var full = this.resolvePath(path);
    try {
      return os.isSymlink(full);
    } catch (e) {
      throw new StorageError("Failed to check symlink '" + path + "': " + e.message);
    }
  }

  /**
   * Reads where a symlink points, as a root-relative path.
   * @param {string} path - Link path.
   * @returns {string} Target path ("" when it points at the root).
   */
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

  /**
   * Checks whether a path exists.
   * @param {string} path - Path to check.
   * @returns {boolean} True when something is there.
   */
  exists(path) {
    var full = this.resolvePath(path);
    try {
      return os.exists(full);
    } catch (e) {
      throw new StorageError("Failed to check existence of '" + path + "': " + e.message);
    }
  }

  /**
   * Lists a folder. Each entry has path, size, date and kind.
   * @param {string} [path] - Folder to list, root when omitted.
   * @param {boolean} [recursive] - Walk into subfolders too.
   * @returns {Array<{path: string, size: number, lastModified: number, isDir: boolean}>} Entries.
   */
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

  /**
   * Renames a file, creating parents at the destination.
   * @param {string} src - Current path.
   * @param {string} dest - New path.
   * @returns {void}
   */
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

  /**
   * Duplicates a file, creating parents at the destination.
   * @param {string} src - Source path.
   * @param {string} dest - Copy destination.
   * @returns {void}
   */
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

  /**
   * Creates a folder and any missing parents.
   * @param {string} path - Folder path.
   * @returns {void}
   */
  makeDir(path) {
    var full = this.resolvePath(path);
    try {
      if (!os.exists(full)) os.mkdir(full, true);
    } catch (e) {
      throw new StorageError("Failed to create directory '" + path + "': " + e.message);
    }
  }

  /**
   * Removes a folder. Refuses non-empty folders unless forced.
   * @param {string} path - Folder path.
   * @param {boolean} [force] - Remove trees, not just empty folders.
   * @returns {void}
   */
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

  /**
   * Creates an empty file when missing, otherwise leaves it alone.
   * @param {string} path - File path.
   * @returns {void}
   */
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

  /**
   * Duplicates a whole folder tree.
   * @param {string} src - Source folder.
   * @param {string} dest - Destination folder.
   * @returns {void}
   */
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

  /**
   * Relocates a whole folder tree.
   * @param {string} src - Source folder.
   * @param {string} dest - Destination folder.
   * @returns {void}
   */
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

  /**
   * Finds files by glob. `*.txt` is top-level only, `** /*.txt`
   * searches everywhere. Sorted, files only, `..` is rejected.
   * @param {string} pattern - Glob like "*.txt" or "** /*.js".
   * @returns {string[]} Matching file paths, sorted.
   */
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

  /**
   * Sets public (`0o644`) or private (`0o600`) permissions.
   * Anything that is not "public" becomes private.
   * @param {string} path - File path.
   * @param {string} visibility - "public" or "private".
   * @returns {void}
   */
  setVisibility(path, visibility) {
    var full = this.resolvePath(path);
    try {
      if (visibility === VIS_PUBLIC) os.chmod(full, 420);
      else os.chmod(full, 384);
    } catch (e) {
      throw new StorageError("Failed to set visibility of '" + path + "': " + e.message);
    }
  }

  /**
   * Reads back public vs private by checking the read bit.
   * @param {string} path - File path.
   * @returns {string} "public" or "private".
   */
  visibility(path) {
    var full = this.resolvePath(path);
    try {
      var mode = os.stat(full).mode;
      return (mode & 4) !== 0 ? VIS_PUBLIC : VIS_PRIVATE;
    } catch (e) {
      throw new StorageError("Failed to get visibility of '" + path + "': " + e.message);
    }
  }

  /**
   * Describes a path: relative name, size, date and kind.
   * @param {string} path - Path to inspect.
   * @returns {{path: string, size: number, lastModified: number, isDir: boolean}} Info object.
   */
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

  /**
   * Size shortcut for metadata().
   * @param {string} path - File path.
   * @returns {number} Size in bytes.
   */
  size(path) {
    return this.metadata(path).size;
  }

  /**
   * Date shortcut for metadata().
   * @param {string} path - File path.
   * @returns {number} Millisecond timestamp.
   */
  lastModified(path) {
    return this.metadata(path).lastModified;
  }

  /**
   * MD5 checksum of a file's text content.
   * @param {string} path - File path.
   * @returns {string} Hex digest.
   */
  checksum(path) {
    var content = this.read(path);
    try {
      return crypto.hash.md5(content);
    } catch (e) {
      throw new StorageError("Failed to checksum '" + path + "': " + e.message);
    }
  }

  /**
   * Guesses the MIME type from the extension.
   * Unknown extensions give `application/octet-stream`.
   * @param {string} path - File path.
   * @returns {string} MIME type.
   */
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

  /**
   * Reads a file as an array of lines (`\r\n` handled, no trailing empty).
   * @param {string} path - File path.
   * @returns {string[]} Lines without endings.
   */
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

/**
 * Creates a driver rooted at the given folder.
 * @param {string} root - Folder to sandbox into, created when missing.
 * @returns {LocalDriver} Ready driver.
 */
function newLocalDriver(root) {
  return new LocalDriver(root);
}

module.exports = { LocalDriver, newLocalDriver, VIS_PUBLIC, VIS_PRIVATE };
