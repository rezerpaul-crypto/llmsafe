# LLMSafe: Umsetzung auf dem Mac

Stand: 23.10.2026. Referenz-main: c761627ad224a6f540d7ae6f06d2c076f426a6a6.

## Was hier bereits fertig ist

Die Konkurrenzrecherche, der technische Entwurf und ein ausführbarer Reproduktions-Harness
für 18 gezielte Fälle liegen vor. Die vorgeschlagenen Änderungen am Scanner sind noch
nicht implementiert. Der Harness startet keine Beispielanwendung und keinen MCP-Server.
Er importiert ausschließlich LLMSafe und lässt den Scanner temporär geschriebene Dateien lesen.

Die zehn G-Fälle beschreiben das gewünschte zukünftige Verhalten. Deshalb ist ein GAP auf dem
Referenzstand erwartbar. Die acht B-/C-Fälle schützen bereits funktionierende Grenzen.
Aus den Zahlen lässt sich keine allgemeine Erkennungsquote ableiten.

## Arbeitsstand sicher auf den Mac holen

Die folgenden Befehle im bereits vorhandenen LLMSafe-Clone ausführen.
Ein neuer Worktree lässt Änderungen im bisherigen Arbeitsordner stehen.

```bash
git fetch origin research/technical-competition-2026-10-23
git worktree add -b review/llmsafe-technical-plan-20261023 ../llmsafe-technical-plan origin/research/technical-competition-2026-10-23
cd ../llmsafe-technical-plan
bash scripts/mac-research-check.sh
```

Existiert der gewählte Worktree oder Branch bereits, den vorhandenen Ordner verwenden oder
einen neuen freien Namen wählen. Kein reset, clean, erzwungenes checkout oder stash nötig.

Voraussetzungen: vorhandenes Git und Python 3.12, 3.13 oder 3.14. Das ist die
empfohlene Entwicklungsumgebung dieses Pakets; LLMSafe behält Python 3.9-3.14 als
Supportvertrag. Bei mehreren Interpretern kann der vorhandene Pfad explizit gesetzt werden:

```bash
LLMSAFE_PYTHON=/opt/homebrew/bin/python3.12 bash scripts/mac-research-check.sh
```

Diesen Beispielpfad nur verwenden, wenn er tatsächlich vorhanden ist. Das Skript installiert
kein Homebrew und verändert kein System-Python. Beim ersten Lauf installiert der vorhandene
Projekt-Workflow die Entwicklungsabhängigkeiten in die lokale .venv und benötigt Netzwerk.
Eine schon vorbereitete Umgebung kann ohne Neuinstallation geprüft werden:

```bash
bash scripts/mac-research-check.sh --check-only
```

Ergebnisse stehen unter build/research/2026-10-23/: quality.log, gaps.json, gaps.txt,
performance.json und die lokale Git-Revision. Der Ordner liegt unter dem bereits ignorierten
build-Verzeichnis. Das Skript führt keinen fetch, checkout, commit, push, Merge oder Release aus.
Die Messung mit 500 Modulen ist eine lokale Entwicklungsprüfung, kein plattformübergreifendes
Geschwindigkeitsversprechen.

## Den nächsten Implementierungslauf beauftragen

Den neuen Arbeitsordner im Mac-Setup öffnen und folgenden Auftrag mitgeben:

> Arbeite ausschließlich im bestehenden Repository rezerpaul-crypto/llmsafe. Lies
> docs/research/2026-10-23/technical-plan.md und diese Datei vollständig. Prüfe den aktuellen
> Git-Stand und offene PRs, insbesondere #44; der dortige Secret-Fix war am 23.10.2026 offen.
> Behalte lokale Änderungen bei. Erstelle einen eigenen Feature-Branch. Beginne mit Paket A
> aus dem technischen Plan: Feld-/Indexzugriffe und konservative Updates für Container.
> Reproduziere zuerst G07 und C03 mit scripts/research_gaps.py. Füge reale Regressionstests
> in tests/test_dataflow.py und tests/test_project_dataflow.py hinzu. Behandle skalare
> Neuzuweisungen, konstante und unbekannte Schlüssel, Aliase, Zweige und Helper-Rückgaben.
> Ändere keine Regel-IDs, keine Python-Supportgrenze und keinen JSON-v1-Vertrag. Gehe
> anschließend nur dann zu Paket B über, wenn A vollständig getestet und als kleiner,
> überprüfbarer Commit abgeschlossen ist. Erfinde keine Sanitizer und importiere oder
> starte niemals gescannten Zielcode. Führe den vollständigen Projekt-Workflow und die
> gezielten Akzeptanzfälle aus. Dokumentiere neu bestandene Fälle, bewusst verbleibende
> Grenzen und die genaue geprüfte Revision. Erstelle bei GitHub-Zugriff einen Draft-PR
> mit der Umsetzung; kein Merge und kein Release als Teil dieses Auftrags.

Das ist ein konkreter erster Arbeitsauftrag, kein automatischer Lauf aller Pakete.
Für weitere Durchläufe das Paket ausdrücklich auf B, C usw. setzen und dessen
Akzeptanzkriterien aus dem technischen Plan übernehmen.

## Befehle zur gezielten Überprüfung

```bash
.venv/bin/python scripts/research_gaps.py
.venv/bin/python scripts/research_gaps.py --json --output build/research/gaps-current.json
.venv/bin/python scripts/research_gaps.py --strict
.venv/bin/python scripts/dev.py --check-only
.venv/bin/python -m benchmarks.performance --modules 500 --budget-seconds 2
```

Der neue Harness hat einen eigenen Exit-Vertrag: 0 bedeutet erfolgreicher
Reproduktionslauf im Entdeckungsmodus, auch bei erwarteten GAPs. Mit --strict bedeutet
1 mindestens eine nicht erfüllte Akzeptanzerwartung. 2 bezeichnet einen Harness- oder
Eingabefehler. Diese Semantik ändert nicht die Exit-Codes der eigentlichen LLMSafe-CLI.

Nach Paket A sollen G07 und C03 passen. Die übrigen offenen G-Fälle bleiben sichtbar.
Erst nach allen zugeordneten Paketen sollen alle 18 Erwartungen erfüllt sein. Der
normale CI-Lauf wird nicht durch diese absichtlich zukünftigen Erwartungen blockiert.

## Referenz und Auswertung

- technical-plan.md: Wettbewerb, Architektur und Arbeitspakete.
- baseline-main.json: gemessene fokussierte Ergebnisse des Referenz-main.
- validation.md: genaue Testumgebung und bereits ausgeführte Prüfungen.
- sources.json: aufgerufene Primärquellen mit Datum.
- benchmarks/research/2026-10-23/cases.json: vollständige reproduzierbare Eingaben.

Die vorgeschlagenen Schwellenwerte für einen späteren Produktvergleich sind Entwicklungsziele.
Die Wettbewerber wurden in dieser Recherche anhand ihrer Primärquellen untersucht und
nicht auf dieser Fallsammlung gegeneinander ausgeführt.
