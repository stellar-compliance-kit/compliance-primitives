import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

const sourceDir = new URL("../docs/interfaces/", import.meta.url);
const outputUrl = new URL("../web/interfaces.html", import.meta.url);

function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function renderMarkdown(markdown) {
  const lines = markdown.replaceAll("\r\n", "\n").split("\n");
  let html = "";
  let inCode = false;
  let inSection = false;
  let code = [];
  for (const line of lines) {
    if (line.trim() === "```text" || line.trim() === "```") {
      if (inCode) {
        html += `<pre class="code"><code>${escapeHtml(code.join("\n"))}</code></pre>`;
        code = [];
      }
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (line.startsWith("# ")) html += `<h1>${escapeHtml(line.slice(2))}</h1>`;
    else if (line.startsWith("## ")) {
      if (inSection) html += "</section>";
      html += `<section class="interface-section"><h2>${escapeHtml(line.slice(3))}</h2>`;
      inSection = true;
    } else if (line.trim()) html += `<p>${escapeHtml(line)}</p>`;
  }
  if (inSection) html += "</section>";
  return html;
}

const files = (await readdir(sourceDir)).filter((file) => file.endsWith(".md")).sort();
const content = [];
for (const file of files) content.push(renderMarkdown(await readFile(join(sourceDir.pathname, file), "utf8")));
const body = content.join("\n") || "<p>No interface documents have been published yet.</p>";
const page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Interfaces — compliance-primitives</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <nav><div class="wrap"><a class="brand" href="index.html">compliance-primitives</a><a href="index.html">Back to overview</a></div></nav>
  <main class="wrap interface-docs">
    <p class="badge">Generated from docs/interfaces</p>
    ${body}
  </main>
  <footer><div class="wrap">MIT License · part of the Drips Wave Stellar Program</div></footer>
</body>
</html>
`;
await writeFile(outputUrl, page);
console.log(`Generated ${basename(outputUrl.pathname)} from ${files.length} Markdown file(s).`);
