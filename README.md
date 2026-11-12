<p align="center">
  <img src="https://github.com/getcarne/carne/blob/main/.github/carne_logo.png" alt="Carne Logo" width="140px" height="140px"><br>
  <strong>flysystem</strong>, sandboxed filesystem for <a href="https://github.com/getcarne/carne">Carne</a><br>
  Local driver with atomic writes, visibility, policies and multi-disk facade on top of <code>std/os</code>.
</p>

<p align="center">
  <code>carne install flysystem</code>
</p>

<p align="center">
  <a href="https://getcarne.github.io/flysystem/">API reference</a><br>
  <img src="https://github.com/getcarne/flysystem/workflows/test/badge.svg" alt="Github Actions">
</p>

## Key Features

- Sandboxed to one root folder, escapes are blocked
- Safe writes (temp file + rename), works with text and binary
- Files and folders: read, write, append, copy, move, delete, list
- Recursive listing and glob search (`*.txt`, `**/*.js`)
- Public / private visibility (`0o644` / `0o600`)
- Safe symlinks that stay inside the root
- File info: size, dates, checksums, mime types, read by lines
- Multiple disks behind one facade (`local`, `cache`, ...)
- Optional policy guard: read-only, size limits, allowed types
- Clear errors (`StorageError`, `FilesystemPolicyError`)


## Usage

```js
const { newLocalDriver } = require("pkg/flysystem");

const d = newLocalDriver("/tmp/uploads");

d.write("hello.txt", "hi");
console.log(d.read("hello.txt")); // "hi"
console.log(d.exists("hello.txt")); // true
```

## API

Local driver (`newLocalDriver(root)`):

- `write(path, content[, visibility])` — atomic tmp + rename write
- `read(path)` / `readBytes(path)` — string / `Uint8Array`
- `append(path, content)`, `delete(path)`, `exists(path)`
- `list(path[, recursive])` — `[{path, size, lastModified, isDir}]`
- `move(src, dest)`, `copy(src, dest)`
- `makeDir(path)`, `deleteDir(path[, force])`, `touch(path)`
- `copyDir(src, dest)`, `moveDir(src, dest)`, `search("*.txt")`
- `metadata(path)`, `size(path)`, `lastModified(path)`
- `checksum(path)` — MD5 hex via `std/crypto` `hash.md5`
- `mimeType(path)` — via `std/mimetype`, `application/octet-stream` fallback
- `setVisibility(path, v)` / `visibility(path)` — `public` (`0o644`) / `private` (`0o600`)
- `createSymlink(path, target)` / `isSymlink(path)` / `readLink(path)` — targets must stay inside the root
- `readLines(path)` — `string[]` split on newlines

All paths are sandboxed to the root. Escapes throw `StorageError`
with `Path traversal detected`.

Multi-disk facade:

```js
const { newFilesystem, newLocalDriver } = require("pkg/flysystem");

const fs = newFilesystem();
fs.addDisk("local", newLocalDriver("/tmp/local"));
fs.addDisk("cache", newLocalDriver("/tmp/cache"));

fs.write("hello.txt", "hi");
fs.disk("cache").write("cached.json", "{}");
```

Policies:

```js
const { newFilesystemPolicy } = require("pkg/flysystem");

const secure = newFilesystemPolicy(driver, {
  readOnly: false,
  maxFileSize: 10 * 1024 * 1024,
  maxPathLength: 255,
  maxDepth: 8,
  denyHiddenFiles: true,
  allowedExtensions: ["txt"],
  allowedMimeTypes: ["text/plain"],
});
```

## Tests

```bash
carne test
carne test local
```

## License

MIT.
