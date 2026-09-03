import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

test("package metadata points consumers at the compiled public entrypoint", () => {
  assert.equal(packageJson.type, "module");
  assert.equal(packageJson.main, "./dist/public.js");
  assert.equal(packageJson.types, "./dist/public.d.ts");
  assert.equal(packageJson.bin["compliance-indexer"], "./dist/index.js");
  assert.deepEqual(packageJson.exports["."], {
    types: "./dist/public.d.ts",
    import: "./dist/public.js",
    default: "./dist/public.js",
  });
  assert.ok(packageJson.files.includes("dist"));
});

test("build emits JavaScript and declaration entrypoints", () => {
  assert.ok(existsSync(join(root, "dist/index.js")));
  assert.ok(existsSync(join(root, "dist/public.d.ts")));
});
