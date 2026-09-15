# pi-anonymizer

Pi extension pro spolehlivou ochranu citlivých údajů (hesel, klíčů, tokenů, jmen a interních identifikátorů) před odesláním do kontextu AI modelu, s **obousměrnou pseudonymizací** a **vícevrstvým blokováním přístupu k citlivým souborům**.

## Hlavní vlastnosti

1. **Obousměrná pseudonymizace (`__ANON_N__`):**
   - Při čtení (`read`, `bash`) jsou citlivé hodnoty nahrazeny stabilními tokeny (např. `__ANON_1__`).
   - Při zápisu nebo editaci (`edit`, `write`, `bash`) plugin **automaticky vrátí původní skutečné hodnoty zpět**.
   - Model nikdy nevidí skutečná hesla, ale kód na disku se nepoškodí žádným statickým `[REDACTED]`.
2. **Slovník známých tajností ze šifrovaného `.env`:**
   - Jména zaměstnanců, interní hostnamy a legacy hesla lze bezpečně předat v `.env`.
   - Podpora šifrování **AES-256-GCM** přímo přes vestavěné Node.js `node:crypto`.
   - Automatická detekce hodnot z běžného `.env` (např. `DB_PASSWORD=...`, `API_KEY=...`).
3. **Striktní ochrana citlivých souborů (Tool & Bash):**
   - **Nástroje (`read`, `read_all`, `edit`, `write`):** Zablokován jakýkoliv přístup k `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`.
   - **Shell (`bash`):** Příkazy přistupující k `.env` nebo klíčům (`cat .env`, `type .env`, `head .env`, `grep ... .env`, `python < .env`) jsou zablokovány před spuštěním.
   - Plugin čte soubory `.env` přímo přes interní Node proces, model k nim nemá přístup.
   - Enforce allowlistu pro čtení (`cwd`, `tmpdir`, nebo `PI_ANONYMIZER_ALLOW`).
4. **Bleskový a deterministický běh:**
   - Žádné zdržování lokálním LLM ani otravnými modálními dialogy přerušujícími práci agenta.

---

## Nastavení citlivých údajů v `.env`

Do kořene projektu můžete umístit `.env` s následujícími volbami:

### Varianta A: Šifrovaný slovník (doporučeno pro týmy a git)

Pomocí příkazu v pi vygenerujete šifrovaný řetězec:

```text
/anonymizer encrypt mojeHeslo123 Jan Novak;Alice Smith;SuperTajneHeslo99
```

A do `.env` vložíte vygenerovaný výstup:

```env
PI_ANONYMIZER_KEY="mojeHeslo123"
PI_ANONYMIZER_WORDS_ENCRYPTED="72e841971c4f283a366a75a0:fb200fe620c9c1e2aedcb3298ae7fa78:09e2a2e53a61621396e583f3..."
```

### Varianta B: Otevřený slovník v lokálním `.env`

```env
PI_ANONYMIZER_WORDS="Jan Novak;Alice Smith;SuperTajneHeslo99;internal-db.corp.local"
```

### Varianta C: Běžné konfigurační proměnné

Jakékoliv proměnné v `.env` končící na `_PASSWORD`, `_SECRET`, `_TOKEN`, `_KEY` plugin automaticky načte do maskovacího slovníku.

---

## Příkazy v pi

| Příkaz | Popis |
| --- | --- |
| `/anonymizer` | Zobrazí stav pluginu, počet aktivních tokenů a položek slovníku |
| `/anonymizer on\|off` | Hlavní vypínač všech ochran |
| `/anonymizer reload` | Znovu načte `.env` a proměnné prostředí bez restartu pi |
| `/anonymizer encrypt <heslo> <text>` | Zašifruje citlivý text (AES-256-GCM) pro vložení do `.env` |
| `/anonymizer add <cesta>` | Přidá povolený kořen adresář pro běžící sezení |
| `/anonymizer <log\|block\|redact> [on\|off]` | Přepne konkrétní funkci |

---

## Co plugin automaticky zachytává (Regex + Slovník)

- **Slovník:** Všechna jména, hesla a výrazy ze zašifrovaného/otevřeného `.env`.
- **Klíče a pověření v kódu:** `password = "..."`, `dbPass: "..."`, `api_key = "..."`, `auth_token: "..."`.
- **Database Connection Strings:** `postgres://admin:tajneHeslo@internal.db:5432/app`.
- **Privátní klíče:** Bloky `-----BEGIN RSA PRIVATE KEY-----`.
- **Cloud a API tokeny:** AWS (`AKIA...`), GitHub (`ghp_...`), Slack (`xox...`), Stripe (`sk_live_...`), JWT (`eyJ...`).
- **Hexadecimální hashe a klíče:** 32+ znakové hex řetězce.

---

## Testování

```bash
npm test        # 23 unit testů (regexy, AES-256-GCM, slovník, unmask, bash guard, file protection)
npm run check   # TypeScript kontrola typů
```
