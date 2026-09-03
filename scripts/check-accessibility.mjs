#!/usr/bin/env node
// Run an automated accessibility audit (axe-core) against web/index.html.
// Run as the "accessibility audit" CI job (.github/workflows/ci.yml, marked
// non-blocking with continue-on-error for now — see the job comment) and
// via `npm --prefix web run check-accessibility` locally.
//
// Checks every combination of viewport width and color scheme the page
// actually supports (see styles.css's `prefers-color-scheme: dark` block
// and the mobile-width `.flow`/`pre.code` scroll containers), since a
// finding like a dark-mode-only contrast failure or a narrow-viewport-only
// scroll region is invisible if you only audit the default desktop/light
// combination.
//
// Usage:
//   node scripts/check-accessibility.mjs
//
// Prerequisites:
//   npm install   (downloads puppeteer's bundled Chromium)
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import puppeteer from "puppeteer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..");
const PAGE_URL = pathToFileURL(path.join(REPO_ROOT, "web", "index.html")).href;
const axeSource = fs.readFileSync(
  path.join(REPO_ROOT, "node_modules", "axe-core", "axe.min.js"),
  "utf8"
);

const CHECKS = [
  { label: "desktop / light", viewport: { width: 1280, height: 800 }, dark: false },
  { label: "desktop / dark", viewport: { width: 1280, height: 800 }, dark: true },
  { label: "mobile / light", viewport: { width: 375, height: 800 }, dark: false },
  { label: "mobile / dark", viewport: { width: 375, height: 800 }, dark: true },
];

const browser = await puppeteer.launch({ headless: true });
let totalViolations = 0;

try {
  for (const { label, viewport, dark } of CHECKS) {
    const page = await browser.newPage();
    await page.setViewport(viewport);
    if (dark) {
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "dark" }]);
    }
    await page.goto(PAGE_URL, { waitUntil: "networkidle0" });
    await page.evaluate(axeSource);
    const results = await page.evaluate(async () => await window.axe.run());

    console.log(`\n=== ${label}: ${results.violations.length} violation type(s) ===`);
    for (const v of results.violations) {
      totalViolations += v.nodes.length;
      console.log(`  [${v.impact}] ${v.id} — ${v.help} (${v.nodes.length} element(s))`);
      console.log(`    ${v.helpUrl}`);
      for (const node of v.nodes) {
        console.log(`    - ${node.target.join(" ")}`);
      }
    }
    await page.close();
  }
} finally {
  await browser.close();
}

console.log("");
if (totalViolations > 0) {
  console.log(`==> accessibility audit found ${totalViolations} violation(s)`);
  process.exit(1);
}
console.log("==> accessibility audit passed, 0 violations");
