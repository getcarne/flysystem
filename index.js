// flysystem: sandboxed local filesystem for Carne.
// OOP port of the Nim flysystem local driver + policy + multi-disk facade.
//
//   const { newLocalDriver } = require("pkg/flysystem");
//   const d = newLocalDriver("/tmp/uploads");
//   d.write("hello.txt", "hi");
//   d.read("hello.txt"); // "hi"

const { LocalDriver, newLocalDriver, VIS_PUBLIC, VIS_PRIVATE } = require("./lib/local.js");
const { Filesystem, newFilesystem } = require("./lib/filesystem.js");
const { FilesystemPolicy, newFilesystemPolicy, defaultPolicyRules } = require("./lib/policy.js");
const { StorageError, FilesystemPolicyError } = require("./lib/errors.js");

module.exports = {
  LocalDriver,
  newLocalDriver,
  Filesystem,
  newFilesystem,
  FilesystemPolicy,
  newFilesystemPolicy,
  defaultPolicyRules,
  StorageError,
  FilesystemPolicyError,
  VIS_PUBLIC,
  VIS_PRIVATE,
};
