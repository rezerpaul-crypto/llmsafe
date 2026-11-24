# LiquidJournal-Landingpage (Nachbau)

Statischer Nachbau der Landingpage von liquidjournal.app (Stand der Vorlage: 24.11.2026),
gebaut mit der ausdrücklichen Erlaubnis des Inhabers. Kein Framework, keine Abhängigkeiten,
ca. 700 KB inklusive Schriften und Grafiken.

## Ansehen

```bash
cd website
python3 -m http.server 8080      # dann http://localhost:8080 öffnen
```

`index.html` lässt sich auch direkt aus dem Dateisystem öffnen. Node wird nur zum Neubauen gebraucht.

## Bearbeiten

| Was | Wo | Danach |
| --- | --- | --- |
| Texte und Struktur | `src/*.html` (ein Abschnitt pro Datei, App-Mockups in `src/mocks/`) | `node scripts/build-html.mjs` |
| Grafiken (Chrom, Berge, Pinguin) | `scripts/build-art.mjs` (deterministisch, Seed-basiert) | `node scripts/build-art.mjs` |
| Farben, Radien, Schriftgrößen | `:root` in `assets/css/base.css`, Dark Mode in `:root[data-theme="dark"]` | nichts |
| Verhalten | `assets/js/main.js` (ein Skript, jede Funktion prüft ihr Markup selbst) | nichts |

`npm run build` im Ordner `website` führt beide Skripte aus. `index.html` ist generiert und eingecheckt.

## Was ist 1:1, was ist ersetzt?

**Nach der Vorlage:** Abschnittsreihenfolge, Layout und Proportionen, Typografie-Charakter, Interaktionen
(Wort-für-Wort-Reveal, scrollgesteuerte Pinguin-Szene, Feature-Tabs, Preis-Umschalter, Marquees),
Produkttexte, USD-Preise, Kennzahlen und der Promo-Code `LIQUID40`.

**Bewusst ersetzt:**

- Alle Bilder und Videos der Vorlage sind nicht übernommen. Die Grafiken sind generierte SVGs, die App-Ansichten
  HTML/CSS-Mockups (scharf, themefähig, keine Videos).
- Schriften: Inter und Instrument Serif (SIL OFL, lokal in `assets/fonts`) statt Satoshi, Gambetta und Geist.
- Prop-Firm- und Broker-Logos sind Monogramm-Platzhalter. Echte Logos nur mit Freigabe der jeweiligen Firma einsetzen.
- Reviews, Namen sowie Affiliate- und Link-Page-Profile sind Beispieldaten und als „sample“ markiert.
- Die Wettbewerber-Tabelle ist anonymisiert (Journal A bis D), die Werte sind nicht geprüft.
- EUR- und JPY-Preise sind angenommene Umrechnungen.

**Vor jeder öffentlichen Nutzung prüfen:** Markenname, Kennzahlen (6.794 Trader usw.), Promo-Code, Wettbewerber-Werte
und die rechtlichen Seiten (Privacy, Terms, Risk disclaimer sind noch nicht gebaut).

## Verbesserungen gegenüber der Vorlage

- **Barrierefreiheit:** semantisches HTML mit einer `h1`, Skip-Link, Tabs mit Pfeiltasten (Roving Tabindex),
  `aria-live`-Hinweise, Tabellen mit Zeilen- und Spaltenköpfen, sichtbare Fokusrahmen, `prefers-reduced-motion`
  mit eigenem statischem Layout für die Szene und die Marquees.
- **Dark Mode:** folgt dem Systemthema, Umschalter mit gespeicherter Wahl.
- **Robustheit:** ohne JavaScript bleibt alles lesbar, Schriftfallback mit angepassten Metriken (kein Layout-Sprung),
  kein horizontales Scrollen bei 320 bis 1440 px, mobile Vergleichstabelle mit angehefteter Label- und Liquid-Spalte.
- **Performance:** keine Rasterbilder, keine Videos, zwei Schriftdateien, Bilder lazy geladen, Scroll-Effekte
  über einen `requestAnimationFrame`-Loop.
- **Preise:** Währungs- und Jahresumschalter rechnen alle Preise inklusive der Rabatt-Chips neu.

## Noch offen

- Unterseiten (Pricing, About, Affiliates, Partners, Support, Legal), Login und Sign-up (tote Links mit Hinweis-Toast).
- Mehrsprachigkeit (die Sprachlinks im Footer sind nur Optik).
- Das Prop-Firm-Briefing und das Repo des Kollegen sind noch nicht eingearbeitet.
