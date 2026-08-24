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
| --- | --- |
| `/anonymizer` | nápověda + přehled allowlistu a stavů přepínačů |
| `/anonymizer add <cesta>` | přidá povolený kořen pro běžící sezení (do restartu pi) |
| `/anonymizer <přepínač> [on\|off]` | přepne funkci (bez argumentu toggluje) |

## Přepínače pro testování

Platí jen pro běžící sezení — po restartu pi se vrátí defaulty.

| Přepínač | Default | Popis |
| --- | --- | --- |
| `log` | ON | notifikace o každém `read`/`bash` volání v UI |
| `block` | ON | blokování `read` mimo allowlist (`/anonymizer block off` = agent čte všude volně) |
| `dialog` | ON | modální dotaz při nálezu citlivých údajů (`off` = automatická anonymizace bez dotazu) |
| `redact` | ON | samotná anonymizace obsahu. **`off` = data jdou modelu neošetřená!** Jen pro test detekce |

Typické scénáře:
- *Chci vidět, co model dostane bez ochrany:* `/anonymizer redact off` → přečti test-secret.txt → `/anonymizer redact on`
- *Neotravuj mě dialogy, jen anonymizuj:* `/anonymizer dialog off`
- *Chci jen sledovat, nic neměnit:* `/anonymizer block off` + `/anonymizer redact off`

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
