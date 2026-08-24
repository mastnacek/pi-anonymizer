# pi-anonymizer

Pi extension, která před odesláním obsahu souborů do kontextu AI modelu
anonymizuje citlivé údaje (hesla, klíče, tokeny) a umí zabránit čtení
souborů mimo povolené cesty.

## Jak to funguje (proof of principle)

Extension používá dva háčky pi architektury:

1. **`tool_call`** — spustí se *před* vykonáním toolu. Když agent zavolá `read`,
   extension zjistí cestu souboru (notify v UI), porovná ji s allowlistem
   a při porušení vrátí `{ block: true }` → soubor se vůbec nepřečte.
2. **`tool_result`** — spustí se *po* vykonání toolu, ale *před tím*,
   než výsledek dorazí modelu. Textový obsah projde anonymizačními regexy.

Allowlist se řídí env proměnnou `PI_ANONYMIZER_ALLOW` (cesty oddělené `;`),
výchozí je aktuální working directory.

## Příkazy v pi

| Příkaz | Popis |
|---|---|
| `/anonymizer` | nápověda + přehled aktuálního allowlistu |
| `/anonymizer add <cesta>` | přidá povolený kořen pro běžící sezení (do restartu pi) |

## Nastavení

- **`PI_ANONYMIZER_ALLOW`** — stálý allowlist, cesty oddělené `;`
  (např. `PI_ANONYMIZER_ALLOW="D:\projekty;C:\Users\me\docs"`).
  Bez nastavení je povolena jen aktuální working directory.
- Vše ostatní (regexy, chování dialogu) je zatím pevně v kódu — konfigurační
  soubor přibude, až bude reálně potřeba.

## Instalace

```bash
npm install
```

## Test principu

```bash
pi -e ./index.ts
```

Poté v pi:

1. **Anonymizace**: „přečti test-secret.txt" — hesla/klíče se zobrazí jako
   `[REDACTED]` a v UI vyskočí notifikace `[anonymizer] obsah z "read" anonymizovan`.
2. **Zastavení čtení**: „přečti C:/Windows/win.ini" (nebo cokoliv mimo allowlist)
   — agent dostane block reason a obsah neuvidí.
3. **Logování**: každý `read` i `bash` call se objeví jako
   `[anonymizer] read -> <cesta>` notifikace.

## Self-check regexů

```bash
node --experimental-strip-types selfcheck.ts
```

## Co je zatím záměrně vynechané

- pseudonymizační mapa (de-anonymizace zpět pro `edit`/`write`)
- anonymizace bash výstupů (jen se logují)
- lokální LLM jako druhá vrstva anonymizace
- pokročilejší patterny (uživatelská jména apod.)
