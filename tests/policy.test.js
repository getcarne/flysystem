const { test, expect } = require("std/test");
const os = require("std/os");
const { newLocalDriver, newFilesystemPolicy } = require("../index.js");

function tmpRoot(name) {
  var base = os.tmpdir() + "/flysystem_" + name + "_" + os.pid();
  if (os.exists(base)) os.removeDir(base, true);
  os.mkdir(base, true);
  return base;
}

function clean(root) {
  if (os.exists(root)) os.removeDir(root, true);
}

test("policy readOnly blocks writes", () => {
  var root = tmpRoot("ro");
  try {
    var raw = newLocalDriver(root);
    var p = newFilesystemPolicy(raw, { readOnly: true });
    var threw = false;
    try {
      p.write("x.txt", "hi");
    } catch (e) {
      threw = e.rule === "readOnly";
    }
    expect(threw).toBe(true);
    // reads still go through (missing file raises StorageError, not policy)
    expect(p.exists("x.txt")).toBe(false);
  } finally {
    clean(root);
  }
});

test("policy maxFileSize bounds writes and reads", () => {
  var root = tmpRoot("size");
  try {
    var raw = newLocalDriver(root);
    var p = newFilesystemPolicy(raw, { maxFileSize: 4 });
    var threw = false;
    try {
      p.write("big.txt", "hello world");
    } catch (e) {
      threw = e.rule === "maxFileSize";
    }
    expect(threw).toBe(true);
    raw.write("ok.txt", "hi");
    expect(p.read("ok.txt")).toBe("hi");
    raw.write("big2.txt", "hello world");
    var threwRead = false;
    try {
      p.read("big2.txt");
    } catch (e) {
      threwRead = e.rule === "maxFileSize";
    }
    expect(threwRead).toBe(true);
  } finally {
    clean(root);
  }
});

test("policy extension and hidden rules", () => {
  var root = tmpRoot("ext");
  try {
    var raw = newLocalDriver(root);
    var p = newFilesystemPolicy(raw, { allowedExtensions: ["txt"], denyHiddenFiles: true });
    var threwExt = false;
    try {
      p.write("evil.exe", "x");
    } catch (e) {
      threwExt = e.rule === "allowedExtensions";
    }
    expect(threwExt).toBe(true);
    p.write("good.txt", "ok");
    expect(p.read("good.txt")).toBe("ok");
    var threwHidden = false;
    try {
      p.write(".secret.txt", "x");
    } catch (e) {
      threwHidden = e.rule === "denyHiddenFiles";
    }
    expect(threwHidden).toBe(true);
  } finally {
    clean(root);
  }
});

test("policy path length and depth", () => {
  var root = tmpRoot("path");
  try {
    var raw = newLocalDriver(root);
    var p = newFilesystemPolicy(raw, { maxPathLength: 5, maxDepth: 2 });
    var threwLen = false;
    try {
      p.write("toolongname.txt", "x");
    } catch (e) {
      threwLen = e.rule === "maxPathLength";
    }
    expect(threwLen).toBe(true);
    var p2 = newFilesystemPolicy(raw, { maxDepth: 2 });
    var threwDepth = false;
    try {
      p2.write("a/b/c.txt", "x");
    } catch (e) {
      threwDepth = e.rule === "maxDepth";
    }
    expect(threwDepth).toBe(true);
  } finally {
    clean(root);
  }
});
