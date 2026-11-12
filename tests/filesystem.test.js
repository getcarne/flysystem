const { test, expect } = require("std/test");
const os = require("std/os");
const { newLocalDriver, newFilesystem } = require("../index.js");

function tmpRoot(name) {
  var base = os.tmpdir() + "/flysystem_" + name + "_" + os.pid();
  if (os.exists(base)) os.removeDir(base, true);
  os.mkdir(base, true);
  return base;
}

function clean(root) {
  if (os.exists(root)) os.removeDir(root, true);
}

test("filesystem multi-disk facade", () => {
  var a = tmpRoot("fsA");
  var b = tmpRoot("fsB");
  try {
    var fs = newFilesystem();
    fs.addDisk("local", newLocalDriver(a));
    fs.addDisk("cache", newLocalDriver(b));
    fs.write("hello.txt", "hi");
    expect(fs.read("hello.txt")).toBe("hi");
    expect(fs.exists("hello.txt")).toBe(true);
    fs.disk("cache").write("cached.json", "{}");
    expect(fs.disk("cache").read("cached.json")).toBe("{}");
    // default disk untouched by cache disk
    expect(fs.exists("cached.json")).toBe(false);
    fs.delete("hello.txt");
    expect(fs.exists("hello.txt")).toBe(false);
  } finally {
    clean(a);
    clean(b);
  }
});

test("filesystem disk policy and rawDisk bypass", () => {
  var a = tmpRoot("fsP");
  try {
    var fs = newFilesystem();
    fs.addDisk("uploads", newLocalDriver(a), { allowedExtensions: ["txt"] });
    fs.disk("uploads").write("ok.txt", "hi");
    var threw = false;
    try {
      fs.disk("uploads").write("bad.bin", "x");
    } catch (e) {
      threw = e.rule === "allowedExtensions";
    }
    expect(threw).toBe(true);
    // rawDisk bypasses the policy
    fs.rawDisk("uploads").write("raw.bin", "x");
    expect(fs.rawDisk("uploads").exists("raw.bin")).toBe(true);
    var threwMissing = false;
    try {
      fs.disk("nope").read("x");
    } catch (e) {
      threwMissing = e.message.indexOf("Disk not found") !== -1;
    }
    expect(threwMissing).toBe(true);
  } finally {
    clean(a);
  }
});
