#!/usr/bin/env node
/**
 * Assembles the site from website/src/*.html partials. No dependencies.
 *
 *   node website/scripts/build-html.mjs
 *
 * Outputs
 *   index.html                 multi-file page for development and hosting (links assets/…)
 *   dist/prop-firm-os.html     one self-contained file: CSS, JS, fonts and artwork inlined
 *   --artifact <path>          optional: the same page without <html>/<head>/<body>, for hosts that wrap it
 *
 * src/index.template.html lists the body partials with  <!--@include name.html-->
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'src');
const CSS = ['base.css', 'hero.css', 'features.css', 'mocks.css', 'more.css'];
const MIME = { '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp' };

const read = (...p) => readFileSync(join(...p), 'utf8');
const warnings = [];

function expand(text, depth = 0) {
  if (depth > 4) throw new Error('include depth exceeded');
  return text.replace(/^([ \t]*)<!--@include\s+([\w./-]+)\s*-->[ \t]*$/gm, (_, indent, name) => {
    const file = join(src, name);
    if (!existsSync(file)) { warnings.push(`missing partial: ${name}`); return ''; }
    const body = expand(read(file).replace(/\s+$/, ''), depth + 1);
    return body.split('\n').map((line) => (line ? indent + line : line)).join('\n');
  });
}

function dataUri(file) {
  const mime = MIME[extname(file)];
  if (!mime) throw new Error(`no mime type for ${file}`);
  return `data:${mime};base64,${readFileSync(file).toString('base64')}`;
}

/* ---- sources ---- */
const head = read(src, 'head.html').trim();
const early = read(src, 'early.js').trim();
const body = expand(read(src, 'index.template.html')).trim();
const js = read(root, 'assets', 'js', 'main.js').trim();
const title = (head.match(/<title>([^<]*)<\/title>/) || [])[1];
const description = (head.match(/<meta name="description" content="([^"]*)"/) || [])[1];
if (!title) throw new Error('head.html needs a <title>');

/* ---- guard: the two dark-token blocks in base.css must not drift apart ---- */
{
  const base = read(root, 'assets', 'css', 'base.css');
  const norm = (m) => (m ? m[1].replace(/\s+/g, ' ').trim() : null);
  const a = norm(base.match(/:root:not\(\[data-theme="light"\]\)\s*\{([^}]*)\}/));
  const b = norm(base.match(/:root\[data-theme="dark"\]\s*\{([^}]*)\}/));
  if (!a || !b) throw new Error('base.css: dark token blocks not found');
  if (a !== b) throw new Error('base.css: the two dark token blocks differ. Keep them identical.');
}

/* ---- 1. multi-file page ---- */
const multi = `<!doctype html>
<html lang="en">
<head>
${head}
<script>
${early}
</script>
</head>
<body>
${body}
<script src="assets/js/main.js" defer></script>
</body>
</html>
`;
writeFileSync(join(root, 'index.html'), multi);

/* ---- 2 + 3. single-file variants ---- */
const cssDir = join(root, 'assets', 'css');
const css = CSS.map((name) => read(cssDir, name).trim())
  .join('\n\n')
  .replace(/url\((['"]?)(\.\.\/(?:img|fonts)\/[^'")]+)\1\)/g, (_, q, rel) => `url("${dataUri(join(cssDir, rel))}")`);
const inlineBody = body
  .replace(/<!--[\s\S]*?-->\n?/g, '') /* authoring notes stay in the source */
  .replace(/\b(src|href)="(assets\/img\/[^"]+)"/g, (_, attr, rel) => `${attr}="${dataUri(join(root, rel))}"`);
const leftovers = (css + inlineBody).match(/(?:\.\.\/|assets\/)(?:img|fonts|css|js)\/[\w./-]+/g);
if (leftovers) throw new Error(`single-file build still references files: ${[...new Set(leftovers)].join(', ')}`);

const core = `<style>
${css}
</style>
<script>
${early}
</script>
${inlineBody}
<script>
${js}
</script>
`;

const standalone = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${title}</title>
<meta name="description" content="${description || ''}">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="${dataUri(join(root, 'assets', 'img', 'favicon.svg'))}">
</head>
<body>
${core}</body>
</html>
`;
const artifact = `<title>${title}</title>
<meta name="claude:viewport-fit-sides" content="cover">
${core}`;

mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist', 'prop-firm-os.html'), standalone);

/* the wrapped variant is only written on request:  --artifact <path> */
const flag = process.argv.indexOf('--artifact');
const artifactPath = flag > -1 ? process.argv[flag + 1] : null;
if (artifactPath) writeFileSync(artifactPath, artifact);

const kb = (s) => `${(Buffer.byteLength(s) / 1024).toFixed(0)} KB`;
console.log(`index.html ${kb(multi)} · dist/prop-firm-os.html ${kb(standalone)}${artifactPath ? ` · ${artifactPath} ${kb(artifact)}` : ''}`);
if (warnings.length) console.log('WARNINGS\n  ' + warnings.join('\n  '));
