# Prop Firm OS – Website

Landingpage für **Prop Firm OS**, die lokale Desktop-App für Futures-Prop-Trader
(Repo `jamach136-collab/prop-firm-os-react`, Stand Version 0.1.0).

Statische Seite ohne Framework und ohne Abhängigkeiten. Eine Datei reicht zum Ausliefern:
`dist/prop-firm-os.html` (rund 530 KB, Schriften und Grafiken sind eingebettet).

## Ansehen

- **Eine Datei:** `dist/prop-firm-os.html` im Browser öffnen oder auf einen beliebigen Webspace legen.
- **Entwicklung:** `cd website && python3 -m http.server 8080`, dann http://localhost:8080 öffnen.

## Bearbeiten

| Was | Wo | Danach |
| --- | --- | --- |
| Texte und Struktur | `src/*.html`, ein Abschnitt pro Datei | `node scripts/build-html.mjs` |
| App-Vorschauen | `src/mocks/*.html` (HTML/CSS nach den echten Screens) | `node scripts/build-html.mjs` |
| Farben, Radien, Schriftgrößen | `:root` in `assets/css/base.css` | `node scripts/build-html.mjs` |
| Grafiken (Chrom, Berge, Figur) | `scripts/build-art.mjs`, deterministisch | `node scripts/build-art.mjs`, dann HTML bauen |
| Verhalten | `assets/js/main.js` | `node scripts/build-html.mjs` |

`npm run build` im Ordner `website` führt beide Skripte aus. `index.html` und `dist/` sind generiert und eingecheckt.

Die dunklen Farbwerte stehen in `base.css` zweimal (Systemthema und Umschalter). Der Build bricht ab, wenn die beiden Blöcke voneinander abweichen.

### Download freischalten

Im letzten Abschnitt steht „Early access. There is no public download yet.“ Sobald es einen Download gibt:
in `assets/js/main.js` oben `GET_URL` setzen. Der Hinweis verschwindet dann und der Button „Download Prop Firm OS“ erscheint.

## Woher die Inhalte kommen

Alle Aussagen auf der Seite stammen aus dem Code der App (`src/App.tsx`):

- **Zahlen in den Vorschauen:** die mitgelieferten Demo-Daten (3 Konten, 4 Trades, +$760.00, 61 % vom Ziel, $1,480.00 Tagesverlust-Spielraum).
- **„The math“:** die Rechenregeln der App (Win ab $1, Break-even $0 bis unter $1, Warnung ab 75 % des Limits, Win-Rate ohne Break-evens usw.).
- **Risk-Monitor-Demo:** dieselbe Formel wie in der App (`remaining = max(0, limit + net)`).
- **Zitat, Notebook-Fragen, Kalenderfilter:** wörtlich aus der App.

Bewusst **nicht** enthalten, weil es dafür keine Grundlage gibt: Kundenstimmen, Nutzerzahlen, Preise, Vergleiche mit namentlich genannten Konkurrenzprodukten.

## Annahmen, die ihr prüfen solltet

- **Kein öffentlicher Download:** Die Seite sagt das so. Stimmt das nicht, `GET_URL` setzen (siehe oben).
- **Sprache:** Englisch, wie die App.
- **Firmennamen in den Vorschauen** (Apex Trader Funding, Topstep, Take Profit Trader) stehen so in den Demo-Daten der App. Die Seite sagt ausdrücklich, dass keine Verbindung zu Prop-Firmen besteht.
- **Kalenderzeilen** in den Vorschauen sind Beispiele und als solche gekennzeichnet.
- **Porsche-Fotos** aus `public/` der App sind nicht übernommen (Bildrechte unklar, fremde Marke). In der Vorschau der Startseite steht an der Stelle die generierte Berg-Grafik.
- **Impressum und Datenschutz** fehlen. Vor einer Veröffentlichung in Deutschland ergänzen.

## Gestaltung

Aufbau und Bildsprache orientieren sich an liquidjournal.app, mit Erlaubnis des Inhabers: weite, ruhige Typografie,
graue Flächen als Bühne, ein Blau als einzige Akzentfarbe, eine scrollgesteuerte Gipfel-Szene.
Farben und die kleinen Versal-Labels stammen aus der App selbst (`LiquidJournalStyle.css`).
Texte, Grafiken und App-Vorschauen sind eigenständig; von der Vorlage sind keine Bilder, Videos, Texte oder Logos übernommen.
Schriften: Inter und Instrument Serif (SIL OFL, liegen in `assets/fonts`).

## Qualität

- Ohne JavaScript bleibt alles lesbar; mit `prefers-reduced-motion` gibt es keine Scroll-Effekte und keine Laufbänder.
- Dark Mode folgt dem System, der Umschalter merkt sich die Wahl.
- Kein seitliches Scrollen von 320 bis 1920 px; die Vergleichstabelle hält auf dem Handy erste und letzte Spalte fest.
- Tastatur: Skip-Link, Tabs mit Pfeiltasten, sichtbarer Fokus. Eine `h1`, Tabellen mit Zeilen- und Spaltenköpfen.
- Keine externen Anfragen, keine Cookies, kein Tracking.
