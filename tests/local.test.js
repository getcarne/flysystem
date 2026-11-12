const { test, expect } = require("std/test");
const os = require("std/os");
const { newLocalDriver } = require("../index.js");

function tmpRoot(name) {
  var base = os.tmpdir() + "/flysystem_" + name + "_" + os.pid();
  if (os.exists(base)) os.removeDir(base, true);
  os.mkdir(base, true);
  return base;
}

function clean(root) {
  if (os.exists(root)) os.removeDir(root, true);
}

test("local basic write/read/exists", () => {
  var root = tmpRoot("basic");
  try {
    var d = newLocalDriver(root);
    expect(d.exists("foo.txt")).toBe(false);
    d.write("foo.txt", "hello world");
    expect(d.exists("foo.txt")).toBe(true);
    expect(d.read("foo.txt")).toBe("hello world");
  } finally {
    clean(root);
  }
});

test("local prevents path traversal", () => {
  var root = tmpRoot("traversal");
  try {
    var d = newLocalDriver(root);
    var threw = false;
    try {
      d.write("../evil.txt", "nope");
    } catch (e) {
      threw = true;
      expect(e.message.indexOf("traversal") !== -1).toBe(true);
    }
    expect(threw).toBe(true);
  } finally {
    clean(root);
  }
});

test("local move and copy", () => {
  var root = tmpRoot("movecopy");
  try {
    var d = newLocalDriver(root);
    d.write("a.txt", "a");
    d.move("a.txt", "sub/b.txt");
    expect(d.exists("a.txt")).toBe(false);
    expect(d.read("sub/b.txt")).toBe("a");
    d.copy("sub/b.txt", "c.txt");
    expect(d.read("c.txt")).toBe("a");
    d.delete("c.txt");
    expect(d.exists("c.txt")).toBe(false);
  } finally {
    clean(root);
  }
});

test("local dirs touch readLines deleteDir", () => {
  var root = tmpRoot("dirs");
  try {
    var d = newLocalDriver(root);
    d.makeDir("assets/images");
    expect(d.exists("assets/images")).toBe(true);
    d.touch("empty.txt");
    expect(d.exists("empty.txt")).toBe(true);
    expect(d.size("empty.txt")).toBe(0);
    d.write("lines.txt", "alpha\nbeta\r\ngamma\n");
    expect(d.readLines("lines.txt")).toEqual(["alpha", "beta", "gamma"]);
    d.write("notrail.txt", "only");
    expect(d.readLines("notrail.txt")).toEqual(["only"]);
    d.makeDir("pop");
    d.write("pop/f.txt", "x");
    var threw = false;
    try {
      d.deleteDir("pop");
    } catch (e) {
      threw = e.message.indexOf("not empty") !== -1;
    }
    expect(threw).toBe(true);
    d.deleteDir("pop", true);
    expect(d.exists("pop")).toBe(false);
  } finally {
    clean(root);
  }
});

test("local metadata size checksum mime visibility", () => {
  var root = tmpRoot("meta");
  try {
    var d = newLocalDriver(root);
    d.write("hello.txt", "hello world");
    expect(d.size("hello.txt")).toBe(11);
    expect(d.checksum("hello.txt")).toBe("5eb63bbbe01eeed093cb22bb8f5acdc3");
    expect(d.mimeType("hello.txt")).toBe("text/plain");
    expect(d.mimeType("noext")).toBe("application/octet-stream");
    var m = d.metadata("hello.txt");
    expect(m.path).toBe("hello.txt");
    expect(m.size).toBe(11);
    expect(m.isDir).toBe(false);
    d.write("secret.txt", "x");
    expect(d.visibility("secret.txt")).toBe("private");
    d.setVisibility("secret.txt", "public");
    expect(d.visibility("secret.txt")).toBe("public");
  } finally {
    clean(root);
  }
});

test("local search copyDir moveDir list", () => {
  var root = tmpRoot("search");
  try {
    var d = newLocalDriver(root);
    d.write("src/a.txt", "a");
    d.write("src/b.log", "b");
    d.write("src/nested/c.txt", "c");
    expect(d.search("src/*.log")).toEqual(["src/b.log"]);
    var all = d.list("", true).map(function (e) { return e.path; }).sort();
    expect(all.indexOf("src/nested/c.txt") !== -1).toBe(true);
    d.copyDir("src", "dst");
    expect(d.exists("dst/nested/c.txt")).toBe(true);
    d.moveDir("dst", "moved");
    expect(d.exists("moved/nested/c.txt")).toBe(true);
    expect(d.exists("dst")).toBe(false);
  } finally {
    clean(root);
  }
});

test("local binary readBytes roundtrip", () => {
  var root = tmpRoot("bin");
  try {
    var d = newLocalDriver(root);
    var src = new Uint8Array(4);
    src[0] = 1; src[1] = 2; src[2] = 250; src[3] = 0;
    d.write("b.bin", src);
    var back = d.readBytes("b.bin");
    expect(back instanceof Uint8Array).toBe(true);
    expect(back.length).toBe(4);
    expect(back[2]).toBe(250);
  } finally {
    clean(root);
  }
});

test("local symlinks stay inside the drive", () => {
  var root = tmpRoot("links");
  try {
    var d = newLocalDriver(root);
    d.write("real.txt", "payload");
    d.createSymlink("alias.txt", "real.txt");
    expect(d.isSymlink("alias.txt")).toBe(true);
    expect(d.isSymlink("real.txt")).toBe(false);
    expect(d.readLink("alias.txt")).toBe("real.txt");
    expect(d.read("alias.txt")).toBe("payload");
    var threw = false;
    try {
      d.createSymlink("bad.txt", "../outside.txt");
    } catch (e) {
      threw = e.message.indexOf("traversal") !== -1;
    }
    expect(threw).toBe(true);
    d.delete("alias.txt");
    expect(d.exists("alias.txt")).toBe(false);
    expect(d.read("real.txt")).toBe("payload");
  } finally {
    clean(root);
  }
});
