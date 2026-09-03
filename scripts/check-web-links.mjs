import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

const webRoot = resolve(new URL("../web/", import.meta.url).pathname);
const htmlFiles = (await readdir(webRoot)).filter((file) => extname(file) === ".html");
const failures = [];
const warnings = [];

function anchorsFor(html) {
  return new Set([...html.matchAll(/(?:id|name)=["']([^"']+)["']/gi)].map((match) => match[1]));
}

for (const file of htmlFiles) {
  const sourcePath = join(webRoot, file);
  const html = await readFile(sourcePath, "utf8");
  const anchors = anchorsFor(html);
  for (const match of html.matchAll(/href=["']([^"'#]+)?(?:#([^"']+))?["']/gi)) {
    const href = match[1] ?? "";
    const fragment = match[2];
    if (!href) {
      if (fragment && !anchors.has(fragment)) failures.push(`${file}: missing anchor #${fragment}`);
      continue;
    }
    if (/^(mailto:|tel:|javascript:)/i.test(href)) continue;
    if (/^https?:\/\//i.test(href)) {
      try {
        const response = await fetch(href, { method: "HEAD", signal: AbortSignal.timeout(8000) });
        if (!response.ok) warnings.push(`${file}: external link returned HTTP ${response.status}: ${href}`);
      } catch (error) {
        warnings.push(`${file}: external link unreachable (${error instanceof Error ? error.message : String(error)}): ${href}`);
      }
      continue;
    }
    const targetPath = resolve(webRoot, href);
    if (!targetPath.startsWith(`${webRoot}/`) || !existsSync(targetPath)) {
      failures.push(`${file}: missing local target ${href}`);
      continue;
    }
    if (fragment) {
      const targetHtml = await readFile(targetPath, "utf8");
      if (!anchorsFor(targetHtml).has(fragment)) failures.push(`${file}: missing anchor ${href}#${fragment}`);
    }
  }
}

for (const warning of warnings) console.warn(`WARN ${warning}`);
if (failures.length) {
  for (const failure of failures) console.error(`ERROR ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Checked ${htmlFiles.length} web page(s); no broken internal links found.`);
}
