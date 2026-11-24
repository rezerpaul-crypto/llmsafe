#!/usr/bin/env node
/**
 * Assembles website/index.html from website/src/*.html partials.
 * The template (src/index.template.html) pulls partials in with
 *   <!--@include name.html-->
 * No dependencies; run after editing any partial:
 *
 *   node website/scripts/build-html.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'src');

function expand(text, depth = 0) {
  if (depth > 4) throw new Error('include depth exceeded');
  return text.replace(/^([ \t]*)<!--@include\s+([\w./-]+)\s*-->[ \t]*$/gm, (_, indent, name) => {
    const body = expand(readFileSync(join(src, name), 'utf8').replace(/\s+$/, ''), depth + 1);
    return body
      .split('\n')
      .map((line) => (line ? indent + line : line))
      .join('\n');
  });
}

const html = expand(readFileSync(join(src, 'index.template.html'), 'utf8'));
writeFileSync(join(root, 'index.html'), html);
console.log(`index.html written (${(html.length / 1024).toFixed(1)} KB)`);
