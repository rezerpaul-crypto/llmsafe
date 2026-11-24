#!/usr/bin/env node
/**
 * Procedural artwork for the Prop Firm OS landing page.
 *
 * Everything the page shows as "photography" (glossy chrome ribbons, snow
 * peaks, the summit scene) is generated here as plain SVG using filter
 * lighting, so the repo ships no raster assets, no third-party imagery and the
 * whole art set weighs a few dozen kilobytes. Re-run after tweaking:
 *
 *   node website/scripts/build-art.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'img');
mkdirSync(OUT, { recursive: true });
const write = (name, svg) => writeFileSync(join(OUT, name), svg.trim() + '\n');

/* ---------- tiny seeded PRNG + helpers ---------- */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const f = (n) => +n.toFixed(1);

/** Midpoint-displacement through control points -> jagged ridge polyline. */
function ridge(ctrl, { seed = 1, depth = 6, rough = 0.5 } = {}) {
  const r = rng(seed);
  let pts = ctrl.map((p) => [...p]);
  let amp = 1;
  for (let d = 0; d < depth; d++) {
    const next = [];
    for (let i = 0; i < pts.length - 1; i++) {
      const [x1, y1] = pts[i];
      const [x2, y2] = pts[i + 1];
      const len = Math.hypot(x2 - x1, y2 - y1);
      next.push(pts[i]);
      next.push([(x1 + x2) / 2 + (r() - 0.5) * len * 0.18 * amp, (y1 + y2) / 2 + (r() - 0.5) * len * rough * amp]);
    }
    next.push(pts[pts.length - 1]);
    pts = next;
    amp *= 0.62;
  }
  return pts;
}
const poly = (pts) => pts.map(([x, y]) => `${f(x)},${f(y)}`).join(' ');

/* ---------- 1. chrome liquid ribbons (hero) ---------- */
function chrome({ id, w, h, paths }) {
  const strokes = paths
    .map((p) => `<path d="${p.d}" stroke="#000" stroke-width="${p.w}" stroke-linecap="round" stroke-linejoin="round" fill="none"/>`)
    .join('\n    ');
  return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="">
  <defs>
    <filter id="${id}" filterUnits="userSpaceOnUse" x="-300" y="-300" width="${w + 600}" height="${h + 700}" color-interpolation-filters="sRGB">
      <feGaussianBlur in="SourceAlpha" stdDeviation="14" result="soft"/>
      <feColorMatrix in="soft" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 26 -11" result="goo"/>
      <feGaussianBlur in="goo" stdDeviation="16" result="height"/>
      <feFlood flood-color="#050507" result="ink"/>
      <feComposite in="ink" in2="goo" operator="in" result="body"/>
      <feDiffuseLighting in="height" surfaceScale="18" diffuseConstant="0.36" lighting-color="#2c3446" result="sheen">
        <feDistantLight azimuth="40" elevation="38"/>
      </feDiffuseLighting>
      <feComposite in="sheen" in2="goo" operator="in" result="sheenIn"/>
      <feSpecularLighting in="height" surfaceScale="16" specularConstant="2.2" specularExponent="46" lighting-color="#ffffff" result="spec">
        <feDistantLight azimuth="228" elevation="48"/>
      </feSpecularLighting>
      <feComposite in="spec" in2="goo" operator="in" result="specIn"/>
      <feSpecularLighting in="height" surfaceScale="12" specularConstant="1.1" specularExponent="30" lighting-color="#b9c6e6" result="rim">
        <feDistantLight azimuth="30" elevation="22"/>
      </feSpecularLighting>
      <feComposite in="rim" in2="goo" operator="in" result="rimIn"/>
      <feGaussianBlur in="goo" stdDeviation="34" result="shadowBlur"/>
      <feOffset in="shadowBlur" dy="26" result="shadowOff"/>
      <feFlood flood-color="#0a1226" flood-opacity="0.22"/>
      <feComposite in2="shadowOff" operator="in" result="shadow"/>
      <feBlend in="sheenIn" in2="body" mode="screen" result="b1"/>
      <feBlend in="rimIn" in2="b1" mode="screen" result="b2"/>
      <feBlend in="specIn" in2="b2" mode="screen" result="b3"/>
      <feMerge><feMergeNode in="shadow"/><feMergeNode in="b3"/></feMerge>
    </filter>
  </defs>
  <g filter="url(#${id})">
    ${strokes}
  </g>
</svg>`;
}

write(
  'chrome-left.svg',
  chrome({
    id: 'cl',
    w: 560,
    h: 1000,
    paths: [
      { d: 'M-120 130 C 90 70 250 150 215 285 C 178 425 20 410 -80 520', w: 118 },
      { d: 'M-90 560 C 60 600 150 690 90 790', w: 86 },
    ],
  }),
);
write(
  'chrome-right.svg',
  chrome({
    id: 'cr',
    w: 640,
    h: 1100,
    paths: [
      { d: 'M760 150 C 560 190 520 330 640 420 C 760 510 720 610 560 650 C 430 684 380 790 470 870 C 560 950 700 920 780 990', w: 150 },
    ],
  }),
);

/* ---------- 2. relief filter shared by every mountain ---------- */
function reliefFilter(id, seed, { snow = 0.5, scale = 22, light = 215, elev = 32, rock = '#4e5e78', snowCol = '#f4f9ff', shadeBlue = '#dfeaff', gx = 0.024, gy = 0.0058, bump = 9 } = {}) {
  // Snow vs rock: source gradient (white at the summit) + noise, thresholded.
  const th = (1.62 - snow * 1.2).toFixed(2);
  return `
    <filter id="${id}" x="-4%" y="-4%" width="108%" height="108%" color-interpolation-filters="sRGB">
      <feTurbulence type="fractalNoise" baseFrequency="0.028" numOctaves="3" seed="${seed}" result="edgeNoise"/>
      <feDisplacementMap in="SourceGraphic" in2="edgeNoise" scale="${scale}" xChannelSelector="R" yChannelSelector="G" result="shape"/>
      <feTurbulence type="fractalNoise" baseFrequency="${gx} ${gy}" numOctaves="6" seed="${seed + 7}" result="gully"/>
      <feColorMatrix in="gully" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  2.1 0 0 0 -0.55" result="bump"/>
      <feDiffuseLighting in="bump" surfaceScale="${bump}" diffuseConstant="1.9" lighting-color="${shadeBlue}" result="shade0">
        <feDistantLight azimuth="${light}" elevation="${elev}"/>
      </feDiffuseLighting>
      <feComponentTransfer in="shade0" result="shade"><feFuncR type="linear" slope="0.62" intercept="0.42"/><feFuncG type="linear" slope="0.62" intercept="0.44"/><feFuncB type="linear" slope="0.58" intercept="0.5"/></feComponentTransfer>
      <feColorMatrix in="shape" type="matrix" values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  1 0 0 0 0" result="lum"/>
      <feTurbulence type="fractalNoise" baseFrequency="0.034 0.0075" numOctaves="5" seed="${seed + 3}" result="snowNoise"/>
      <feColorMatrix in="snowNoise" type="matrix" values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  1 0 0 0 0" result="sn"/>
      <feComposite in="lum" in2="sn" operator="arithmetic" k1="0" k2="1" k3="0.9" k4="-${th}" result="mask0"/>
      <feComponentTransfer in="mask0" result="mask"><feFuncA type="linear" slope="8" intercept="0"/></feComponentTransfer>
      <feFlood flood-color="${rock}" result="rockFill"/>
      <feComposite in="rockFill" in2="shape" operator="in" result="rockIn"/>
      <feFlood flood-color="${snowCol}" result="snowFill"/>
      <feComposite in="snowFill" in2="mask" operator="in" result="snowIn"/>
      <feComposite in="snowIn" in2="rockIn" operator="over" result="albedo"/>
      <feBlend in="albedo" in2="shade" mode="multiply" result="lit"/>
      <feComposite in="lit" in2="shape" operator="in"/>
    </filter>`;
}

/** A horn-shaped silhouette: stepped shoulders on the left, a steeper face on the right. */
function hornProfile({ seed, sx, sy, bl, br, baseY, steps = 9 }) {
  const r = rng(seed);
  const H = baseY - sy;
  const left = [];
  for (let i = 0; i <= steps; i++) {
    const u = i / steps;
    const stair = (i % 2 ? 0.045 : -0.02) * H * (1 - u);
    left.push([bl + (sx - bl) * Math.pow(u, 1.18) + (r() - 0.5) * 26, baseY - H * Math.pow(u, 0.82) + stair + (r() - 0.5) * 24]);
  }
  left[left.length - 1] = [sx, sy];
  const right = [];
  for (let i = 1; i <= steps; i++) {
    const u = i / steps;
    const notch = i === Math.round(steps * 0.45) ? -0.05 * H : 0;
    right.push([sx + (br - sx) * Math.pow(u, 1.05) + (r() - 0.5) * 26, sy + H * Math.pow(u, 0.9) + notch + (r() - 0.5) * 24]);
  }
  right[right.length - 1] = [br, baseY];
  const pts = ridge([...left, ...right], { seed: seed + 5, depth: 5, rough: 0.5 });
  let top = 0;
  pts.forEach((p, i) => { if (p[1] < pts[top][1]) top = i; });
  return { pts, top };
}

function mountainSvg({ id, w, h, seed, peaks, fogTop = true, grad = ['#ffffff', '#6d7a90'], opts = {} }) {
  const shapes = [];
  const grads = [];
  peaks.forEach((p, i) => {
    const { pts, top } = hornProfile({ seed: seed + i * 19, ...p });
    // Ridge line splitting the sunlit face (right) from the shaded face (left).
    const [sx, sy] = pts[top];
    const bx = sx - (p.shade ?? 0.18) * (p.right - p.left);
    const rl = ridge([[sx, sy], [sx + (bx - sx) * 0.4, sy + (p.baseY - sy) * 0.35], [bx, p.baseY]], { seed: seed + i * 7 + 2, depth: 6, rough: 0.34 });
    const shadeFace = [[p.left, h + 60], ...pts.slice(0, top + 1), ...rl.slice(1), [bx, h + 60]];
    const litFace = [...rl.slice().reverse(), ...pts.slice(top + 1), [p.right, h + 60], [bx, h + 60]];
    shapes.push(`<polygon points="${poly(shadeFace)}" fill="url(#s${id}${i})"/>`, `<polygon points="${poly(litFace)}" fill="url(#l${id}${i})"/>`);
    grads.push(
      `<linearGradient id="l${id}${i}" gradientUnits="userSpaceOnUse" x1="0" y1="${p.summitY ?? sy}" x2="0" y2="${p.baseY}"><stop offset="0" stop-color="#fff"/><stop offset="0.55" stop-color="#d4deec"/><stop offset="1" stop-color="${grad[1]}"/></linearGradient>`,
      `<linearGradient id="s${id}${i}" gradientUnits="userSpaceOnUse" x1="0" y1="${p.summitY ?? sy}" x2="0" y2="${p.baseY}"><stop offset="0" stop-color="#a7b4c9"/><stop offset="0.5" stop-color="#5e6d86"/><stop offset="1" stop-color="#384560"/></linearGradient>`,
    );
  });
  return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="">
  <defs>
    ${grads.join('')}
    ${reliefFilter('rel' + id, seed, opts)}
    ${fogTop ? `<linearGradient id="fog${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0.5" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#fff" stop-opacity="1"/></linearGradient>` : ''}
  </defs>
  <g filter="url(#rel${id})">
      ${shapes.join('\n      ')}
  </g>
  ${fogTop ? `<rect width="${w}" height="${h}" fill="url(#fog${id})"/>` : ''}
</svg>`;
}

/* side peaks used behind the story card + showcase */
write(
  'peak-left.svg',
  mountainSvg({
    id: 'pl',
    fogTop: false,
    w: 640,
    h: 760,
    seed: 5,
    peaks: [{ left: -200, right: 560, sx: 140, sy: 50, bl: -200, br: 560, baseY: 760 }],
    opts: { snow: 0.46, light: 305 },
  }),
);
write(
  'peak-right.svg',
  mountainSvg({
    id: 'pr',
    fogTop: false,
    w: 640,
    h: 760,
    seed: 14,
    peaks: [{ left: 60, right: 820, sx: 470, sy: 70, bl: 60, br: 820, baseY: 760 }],
    opts: { snow: 0.5, light: 305 },
  }),
);

/* ---------- 3. summit scene layers ---------- */
write(
  'scene-sky.svg',
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" role="img" aria-label="">
  <defs>
    <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#0b4aa8"/><stop offset="0.3" stop-color="#2273cc"/><stop offset="0.55" stop-color="#6aa6e0"/><stop offset="0.78" stop-color="#bcd6ef"/><stop offset="1" stop-color="#eef5fc"/>
    </linearGradient>
    <filter id="cl" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
      <feTurbulence type="fractalNoise" baseFrequency="0.0028 0.0105" numOctaves="6" seed="17" result="n"/>
      <feColorMatrix in="n" type="matrix" values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 3.6 -1.72"/>
    </filter>
    <filter id="cl2" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
      <feTurbulence type="fractalNoise" baseFrequency="0.006 0.03" numOctaves="5" seed="5" result="n"/>
      <feColorMatrix in="n" type="matrix" values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 4.2 -2.15"/>
    </filter>
    <linearGradient id="cm" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset="0.22" stop-color="#fff" stop-opacity="0.95"/><stop offset="0.62" stop-color="#fff" stop-opacity="0.95"/><stop offset="0.9" stop-color="#fff" stop-opacity="0"/></linearGradient>
    <mask id="cmask"><rect width="1600" height="900" fill="url(#cm)"/></mask>
  </defs>
  <rect width="1600" height="900" fill="url(#sky)"/>
  <g mask="url(#cmask)"><rect width="1600" height="900" filter="url(#cl)" opacity="0.78"/><rect width="1600" height="900" filter="url(#cl2)" opacity="0.9"/></g>
</svg>`,
);

write(
  'scene-range.svg',
  mountainSvg({
    id: 'rg',
    w: 1600,
    h: 900,
    seed: 23,
    fogTop: false,
    peaks: [
      { left: -260, right: 760, sx: 250, sy: 330, bl: -260, br: 760, baseY: 780, steps: 7, shade: 0.2 },
      { left: 480, right: 1260, sx: 880, sy: 400, bl: 480, br: 1260, baseY: 780, steps: 7, shade: 0.2 },
      { left: 980, right: 1960, sx: 1450, sy: 350, bl: 980, br: 1960, baseY: 780, steps: 7, shade: 0.2 },
    ],
    grad: ['#f2f7ff', '#5d6c86'],
    opts: { snow: 0.44, light: 305, scale: 16, rock: '#52627c' },
  }),
);

write(
  'scene-peak.svg',
  mountainSvg({
    id: 'mp',
    w: 1600,
    h: 900,
    seed: 61,
    fogTop: false,
    peaks: [{ left: 300, right: 1400, sx: 930, sy: 90, bl: 300, br: 1400, baseY: 840, steps: 11, shade: 0.22 }],
    grad: ['#ffffff', '#566580'],
    opts: { snow: 0.38, light: 305, elev: 32, scale: 22, rock: '#46566f' },
  }),
);

write(
  'scene-fog.svg',
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" role="img" aria-label="">
  <defs>
    <linearGradient id="band" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#eaf2fb" stop-opacity="0"/><stop offset="0.55" stop-color="#eaf2fb" stop-opacity="0.95"/><stop offset="1" stop-color="#eaf2fb" stop-opacity="0"/></linearGradient>
    <filter id="mist" x="-10%" y="-80%" width="120%" height="260%"><feTurbulence type="fractalNoise" baseFrequency="0.0035 0.025" numOctaves="4" seed="4" result="n"/><feDisplacementMap in="SourceGraphic" in2="n" scale="90" xChannelSelector="R" yChannelSelector="G"/><feGaussianBlur stdDeviation="14"/></filter>
  </defs>
  <g filter="url(#mist)">
    <rect x="-100" y="380" width="1800" height="150" fill="url(#band)"/>
    <rect x="-100" y="440" width="1800" height="110" fill="url(#band)"/>
    <rect x="-100" y="300" width="1800" height="120" fill="url(#band)" opacity="0.5"/>
  </g>
</svg>`,
);

write(
  'scene-snow.svg',
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMax slice" role="img" aria-label="">
  <defs>
    <linearGradient id="field" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#eef5fc"/><stop offset="0.4" stop-color="#c7d8ee"/><stop offset="1" stop-color="#4f7fca"/></linearGradient>
    <filter id="drift" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
      <feTurbulence type="fractalNoise" baseFrequency="0.0022 0.045" numOctaves="3" seed="12" result="n"/>
      <feColorMatrix in="n" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  1.7 0 0 0 -0.35" result="bump"/>
      <feDiffuseLighting in="bump" surfaceScale="3.2" diffuseConstant="1.25" lighting-color="#f7fbff" result="lit0"><feDistantLight azimuth="270" elevation="44"/></feDiffuseLighting>
      <feComponentTransfer in="lit0" result="lit"><feFuncR type="linear" slope="0.36" intercept="0.68"/><feFuncG type="linear" slope="0.36" intercept="0.7"/><feFuncB type="linear" slope="0.3" intercept="0.78"/></feComponentTransfer>
      <feBlend in="SourceGraphic" in2="lit" mode="multiply" result="m"/>
      <feComposite in="m" in2="SourceGraphic" operator="in"/>
    </filter>
    <linearGradient id="horizon" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#eaf2fb" stop-opacity="0"/><stop offset="0.5" stop-color="#eaf2fb" stop-opacity="0.9"/><stop offset="1" stop-color="#eaf2fb" stop-opacity="0"/></linearGradient>
  </defs>
  <path d="M-20 478 C 400 462 1200 462 1620 478 L1620 910 L-20 910Z" fill="url(#field)" filter="url(#drift)"/>
  <rect y="440" width="1600" height="90" fill="url(#horizon)"/>
</svg>`,
);

write(
  'scene-walker.svg',
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 60 100" role="img" aria-label="A hiker walking toward the summit">
  <defs>
    <linearGradient id="wj" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#232c3b"/><stop offset="1" stop-color="#0b0f16"/></linearGradient>
    <linearGradient id="wp" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4f7df2"/><stop offset="1" stop-color="#1440b8"/></linearGradient>
  </defs>
  <ellipse cx="30" cy="95" rx="15" ry="3.4" fill="#0a1a3a" opacity="0.28"/>
  <path d="M52 30 53.5 93" stroke="#39445a" stroke-width="1.6" stroke-linecap="round"/>
  <path d="M22 60 19.5 90c-.2 2.2 1 3.2 3.4 3.2h3.4c1.6 0 2.4-.8 2.6-2.4L30 70l1.6 20.8c.2 1.6 1 2.4 2.6 2.4h3.4c2.4 0 3.6-1 3.4-3.2L38 60z" fill="#0d121a"/>
  <path d="M16.5 34c-3 6-4.6 13-4.4 20 .1 2.6 3.6 2.8 4.2.2l3-13zM43.500 34c3 6 4.600 13 4.400 20-.1 2.600-3.600 2.800-4.200.2l-3-13z" fill="#161d29"/>
  <path d="M30 24c-8 0-13 4-13.500 11L15 60c5 3 25 3 30 0l-1.500-25C43 28 38 24 30 24z" fill="url(#wj)"/>
  <rect x="20.500" y="29" width="19" height="25" rx="6.500" fill="url(#wp)"/>
  <path d="M24 37h12M24 42.500h12" stroke="#fff" stroke-opacity="0.35" stroke-width="1.300" stroke-linecap="round"/>
  <circle cx="30" cy="14.500" r="8.200" fill="#121821"/>
  <path d="M22.300 12.500c1.400-4.600 4.300-6.900 7.700-6.900s6.300 2.300 7.700 6.900c-2.300-1.600-4.900-2.400-7.700-2.400s-5.400.8-7.700 2.400z" fill="#2059e7"/>
</svg>`,
);

write(
  'scene-trail.svg',
  (() => {
    // Alternating footprints in perspective: big at the viewer, tiny at the hiker.
    const prints = [];
    const N = 22;
    for (let i = 0; i < N; i++) {
      const t = i / (N - 1); // 0 = far (top), 1 = near (bottom)
      const y = 14 + Math.pow(t, 1.55) * 586;
      const s = 0.16 + Math.pow(t, 1.4) * 1.0;
      const sway = Math.sin(t * 5.2) * 10 * s;
      const side = i % 2 ? 1 : -1;
      const x = 100 + sway + side * 15 * s;
      prints.push(
        `<g transform="translate(${f(x)} ${f(y)}) rotate(${f(side * 5)}) scale(${f(s)})"><ellipse rx="9.5" ry="14.5" fill="#2a4a86" opacity="0.5"/><ellipse rx="7.4" ry="12" cy="-1.5" fill="#eef4ff" opacity="0.55"/></g>`,
      );
    }
    return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 600" preserveAspectRatio="none" role="img" aria-label="">
  ${prints.join('\n  ')}
</svg>`;
  })(),
);

/* ---------- 4. misty blue vista (community panel, link page, affiliate) ---------- */
write(
  'vista.svg',
  (() => {
    const layers = [
      { seed: 3, y: 330, amp: 90, col: '#c4d8ee', op: 0.9 },
      { seed: 8, y: 400, amp: 120, col: '#9fbede', op: 0.95 },
      { seed: 15, y: 480, amp: 150, col: '#7aa0cc', op: 1 },
    ];
    const polys = layers
      .map((l, i) => {
        const ctrl = [];
        for (let x = -100; x <= 1700; x += 150) ctrl.push([x, l.y - Math.abs(Math.sin(x * 0.0041 + l.seed)) * l.amp]);
        const pts = ridge(ctrl, { seed: l.seed, depth: 5, rough: 0.28 });
        return `<polygon points="${poly([...pts, [1700, 900], [-100, 900]])}" fill="${l.col}" opacity="${l.op}"/>`;
      })
      .join('\n    ');
    return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" role="img" aria-label="">
  <defs>
    <linearGradient id="vs" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#a9cdf0"/><stop offset="0.55" stop-color="#e6f0fa"/></linearGradient>
    <linearGradient id="vm" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#fff" stop-opacity="0.85"/></linearGradient>
    ${reliefFilter('vr', 31, { snow: 0.62, scale: 12, rock: '#7f98bd', gx: 0.0075, gy: 0.0026, bump: 3.2, light: 305 })}
  </defs>
  <rect width="1600" height="900" fill="url(#vs)"/>
  <g filter="url(#vr)">
    ${polys}
  </g>
  <rect y="420" width="1600" height="480" fill="url(#vm)"/>
</svg>`;
  })(),
);

console.log('Art written to', OUT);
