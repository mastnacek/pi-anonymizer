// pi-anonymizer
//
// 1. tool_call   -> Zastavi cteni/zapis chranenych souboru (.env, klice) a cesty mimo allowlist.
//                   Obousmerne de-anonymizuje (unmask) argumenty pro write/edit/bash pred vykonanim.
// 2. tool_result -> Pseudonymizuje citlivy obsah (slovnik ze zasifrovaneho .env + regexy)
//                   pomoci reverzibilnich tokenu __ANON_N__, nez dorazi do kontextu modelu.
//
// Spusteni: pi -e ./index.ts
// Ovladani: /anonymizer

import {
	createCipheriv,
	createDecipheriv,
	randomBytes,
	scryptSync,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import type { AutocompleteItem } from "@earendil-works/pi-tui";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

// --- krypto & trezor pro slovnik --------------------------------------------

const CRYPTO_SALT = "pi-anonymizer-salt";

/** Zasifruje citlivy text pomoci AES-256-GCM.
 *  Vystup: ivHex:authTagHex:cipherHex */
export function encryptSecrets(plainText: string, passphrase: string): string {
	const key = scryptSync(passphrase, CRYPTO_SALT, 32);
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	const enc = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return `${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
}

/** Desifruje payload zasifrovany funkci encryptSecrets. */
export function decryptSecrets(
	payload: string,
	passphrase: string,
): string | null {
	try {
		const [ivHex, tagHex, dataHex] = payload.split(":");
		if (!ivHex || !tagHex || !dataHex) return null;
		const key = scryptSync(passphrase, CRYPTO_SALT, 32);
		const decipher = createDecipheriv(
			"aes-256-gcm",
			key,
			Buffer.from(ivHex, "hex"),
		);
		decipher.setAuthTag(Buffer.from(tagHex, "hex"));
		const dec = Buffer.concat([
			decipher.update(Buffer.from(dataHex, "hex")),
			decipher.final(),
		]);
		return dec.toString("utf8");
	} catch {
		return null;
	}
}

/** Chranene soubory — agent je NESMI cist ani menit (ani pres bash/read/edit/write). */
export function isProtectedPath(path: string): boolean {
	const norm = path.replace(/\\/g, "/").toLowerCase();
	const base = norm.split("/").pop() ?? "";
	if (base === ".env" || base.startsWith(".env.")) return true;
	if (
		base.endsWith(".pem") ||
		base.endsWith(".key") ||
		base.endsWith(".p12") ||
		base.endsWith(".pfx")
	) {
		return true;
	}
	if (
		base === "id_rsa" ||
		base === "id_ed25519" ||
		base === "id_ecdsa" ||
		base === "id_dsa"
	) {
		return true;
	}
	return false;
}

/** Detekce pristupu k .env a klicum v shell prikazech (bash). */
export function isBashProtected(command: string): boolean {
	return (
		/(?:^|[\s/\\"'`;&|<>,])(?:\.[/\\])*\.env(?:\.[\w-]+)*(?:[\s/\\"'`;&|<>,]|$)/i.test(
			command,
		) ||
		/\b(?:id_rsa|id_ed25519|id_ecdsa)\b/i.test(command) ||
		/\.(?:pem|key|p12|pfx)\b/i.test(command)
	);
}

/** Pomocne parsovani .env souboru. */
export function parseDotenv(content: string): Record<string, string> {
	const result: Record<string, string> = {};
	for (const line of content.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;
		const eqIdx = trimmed.indexOf("=");
		if (eqIdx === -1) continue;
		const key = trimmed.slice(0, eqIdx).trim();
		let val = trimmed.slice(eqIdx + 1).trim();
		if (
			(val.startsWith('"') && val.endsWith('"')) ||
			(val.startsWith("'") && val.endsWith("'"))
		) {
			val = val.slice(1, -1);
		}
		result[key] = val;
	}
	return result;
}

// --- konfigurace & slovnik ---------------------------------------------------

const defaultRoots = [process.cwd(), tmpdir()];
export const allowedRoots: string[] = (
	process.env.PI_ANONYMIZER_ALLOW ?? defaultRoots.join(";")
)
	.split(";")
	.map((p) => p.trim())
	.filter(Boolean);

export const isAllowedPath = (path: string): boolean => {
	const abs = isAbsolute(path)
		? resolve(path)
		: resolve(join(process.cwd(), path));
	return allowedRoots.some((root) => {
		const r = resolve(root);
		return abs === r || abs.startsWith(r + sep);
	});
};

export const features = {
	enabled: true, // hlavni master switch
	log: true, // notifikace v UI
	block: true, // blokovat cteni mimo allowlist a pristupy k .env/klicum
	redact: true, // obousmerna pseudonymizace hesel, klicu a slovniku
};

export const TOGGLE_DOCS: Record<string, string> = {
	log: "notifikace o kazdem read/bash volani a redakci v UI",
	block: "zablokuje pristupy k citlivym souborum (.env, klice) a mimo allowlist",
	redact: "obousmerna pseudonymizace (__ANON_N__) hesel, klicu a slovniku",
};

/** Mnozina citlivych slov / jmen / hesel nactenych ze slovniku. */
export const dictionary = new Set<string>();

/** Nacte citliva slova z env promennych a z lokalniho .env souboru. */
export function loadDictionary(cwd: string = process.cwd()): {
	count: number;
	sources: string[];
} {
	dictionary.clear();
	const sources: string[] = [];

	// 1. Z primych env promennych procesu
	if (process.env.PI_ANONYMIZER_WORDS) {
		const words = process.env.PI_ANONYMIZER_WORDS.split(/[;,]/)
			.map((w) => w.trim())
			.filter((w) => w.length >= 3);
		for (const w of words) dictionary.add(w);
		if (words.length > 0) sources.push("env:PI_ANONYMIZER_WORDS");
	}

	// Zasifrovany slovnik v env promenne
	if (
		process.env.PI_ANONYMIZER_WORDS_ENCRYPTED &&
		process.env.PI_ANONYMIZER_KEY
	) {
		const decrypted = decryptSecrets(
			process.env.PI_ANONYMIZER_WORDS_ENCRYPTED,
			process.env.PI_ANONYMIZER_KEY,
		);
		if (decrypted) {
			const words = decrypted
				.split(/[;,\n]/)
				.map((w) => w.trim())
				.filter((w) => w.length >= 3);
			for (const w of words) dictionary.add(w);
			if (words.length > 0) sources.push("env:PI_ANONYMIZER_WORDS_ENCRYPTED");
		}
	}

	// 2. Ze souboru .env a .env.local na disku (cteme bezpecne v pluginu)
	const envCandidates = [join(cwd, ".env"), join(cwd, ".env.local")];
	for (const envFile of envCandidates) {
		if (existsSync(envFile)) {
			try {
				const envContent = readFileSync(envFile, "utf8");
				const parsed = parseDotenv(envContent);

				if (parsed.PI_ANONYMIZER_WORDS) {
					const words = parsed.PI_ANONYMIZER_WORDS.split(/[;,]/)
						.map((w) => w.trim())
						.filter((w) => w.length >= 3);
					for (const w of words) dictionary.add(w);
					sources.push(`${envFile} (PI_ANONYMIZER_WORDS)`);
				}

				const encPayload = parsed.PI_ANONYMIZER_WORDS_ENCRYPTED;
				const encKey = parsed.PI_ANONYMIZER_KEY || process.env.PI_ANONYMIZER_KEY;
				if (encPayload && encKey) {
					const decrypted = decryptSecrets(encPayload, encKey);
					if (decrypted) {
						const words = decrypted
							.split(/[;,\n]/)
							.map((w) => w.trim())
							.filter((w) => w.length >= 3);
						for (const w of words) dictionary.add(w);
						sources.push(`${envFile} (PI_ANONYMIZER_WORDS_ENCRYPTED)`);
					}
				}

				// Automaticky pridame hodnoty zjevnych tajnosti z .env (napr. DB_PASSWORD, API_KEY)
				for (const [key, val] of Object.entries(parsed)) {
					if (
						/(password|passwd|pwd|secret|token|api[-_]?key|auth[-_]?key|private[-_]?key)$/i.test(
							key,
						)
					) {
						if (
							val &&
							val.length >= 4 &&
							!["true", "false", "0", "1", "null", "undefined", "none"].includes(
								val.toLowerCase(),
							)
						) {
							dictionary.add(val);
							sources.push(`${envFile} (${key})`);
						}
					}
				}
			} catch {
				// Ignorujeme chyby cteni .env
			}
		}
	}

	return { count: dictionary.size, sources };
}

// Inicialni nacteni slovniku
loadDictionary();

// --- obousmerna pseudonymizace (Token Vault) --------------------------------

class PseudonymVault {
	private realToToken = new Map<string, string>();
	private tokenToReal = new Map<string, string>();
	private counter = 1;

	getOrCreateToken(real: string): string {
		const existing = this.realToToken.get(real);
		if (existing) return existing;

		const token = `__ANON_${this.counter++}__`;
		this.realToToken.set(real, token);
		this.tokenToReal.set(token, real);
		return token;
	}

	unmask(text: string): string {
		if (!text || this.tokenToReal.size === 0) return text;
		return text.replace(/__ANON_\d+__/g, (match) => {
			return this.tokenToReal.get(match) ?? match;
		});
	}

	clear(): void {
		this.realToToken.clear();
		this.tokenToReal.clear();
		this.counter = 1;
	}

	get size(): number {
		return this.tokenToReal.size;
	}
}

export const vault = new PseudonymVault();

const escapeRegExp = (s: string): string =>
	s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Maskuje citlive udaje v textu: slovnik + generic regexy -> __ANON_N__. */
export function maskText(text: string): { masked: string; changed: boolean } {
	let current = text;
	let changed = false;

	// 1. Slovnik presnych hesel a jmen (serazeny od nejdelsich, aby neorezaval podslova)
	if (dictionary.size > 0) {
		const words = Array.from(dictionary).sort((a, b) => b.length - a.length);
		const dictRegex = new RegExp(words.map(escapeRegExp).join("|"), "g");
		const afterDict = current.replace(dictRegex, (match) => {
			changed = true;
			return vault.getOrCreateToken(match);
		});
		current = afterDict;
	}

	// 2. PEM privatni klice (celkove bloky)
	const pemRegex =
		/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;
	current = current.replace(pemRegex, (match) => {
		changed = true;
		return vault.getOrCreateToken(match);
	});

	// 3. Database connection stringy s hesly: proto://user:password@host:port/db
	const connRegex =
		/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/]+:)([^@\s/]+)(@[^\s/]+)/g;
	current = current.replace(connRegex, (_m, prefix, secret, suffix) => {
		if (secret.length >= 4) {
			changed = true;
			const token = vault.getOrCreateToken(secret);
			return `${prefix}${token}${suffix}`;
		}
		return _m;
	});

	// 4. Klicova slova typu password/secret/token/api_key/auth/dbPass
	const kvRegex =
		/(?<![a-zA-Z0-9])([a-zA-Z0-9_]*?)(pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|auth(?:[-_]?token)?|bearer)(\s*[:=]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[A-Za-z0-9_\-./+]{8,})/gi;
	current = current.replace(kvRegex, (_m, pre, keyword, sep, val) => {
		changed = true;
		const isQuoted =
			(val.startsWith('"') && val.endsWith('"')) ||
			(val.startsWith("'") && val.endsWith("'"));
		const rawVal = isQuoted ? val.slice(1, -1) : val;
		const token = vault.getOrCreateToken(rawVal);
		return isQuoted
			? `${pre}${keyword}${sep}"${token}"`
			: `${pre}${keyword}${sep}${token}`;
	});

	// 5. Vendor tokeny (AWS, GitHub, Slack, Stripe) a JWT
	const vendorRegex =
		/\b(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{36,}|xox[baprs]-[0-9A-Za-z-]{10,}|(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g;
	current = current.replace(vendorRegex, (match) => {
		changed = true;
		return vault.getOrCreateToken(match);
	});

	// 6. Dlouhe hexadecimalni retezce (32+ znaku, md5/sha256 klice)
	current = current.replace(/\b[0-9a-fA-F]{32,}\b/g, (match) => {
		changed = true;
		return vault.getOrCreateToken(match);
	});

	return { masked: current, changed };
}

/** Zpetna kompatibilita: anonymizace textu (vraci primo retezcove). */
export const anonymizeText = (text: string): string => maskText(text).masked;

/** Obousmerne obnoveni puvodnich tajnosti z tokenu __ANON_N__. */
export const unmaskText = (text: string): string => vault.unmask(text);

// --- extension ---------------------------------------------------------------

const refreshStatus = (ctx: ExtensionContext) => {
	// Status is a UI affordance; never call ctx.ui.* in a headless session.
	if (!ctx.hasUI) return;
	if (!features.enabled) {
		ctx.ui.setStatus("anonymizer", "anon off");
		return;
	}
	ctx.ui.setStatus(
		"anonymizer",
		`anon ${features.redact ? "R" : "·"}${features.block ? "B" : "·"} · dict:${dictionary.size} · tok:${vault.size}`,
	);
};

export default function (pi: ExtensionAPI) {
	const CONFIG_ENTRY_TYPE = "pi-anonymizer-config";

	/** UI-safe notify: no-op when running headless (AGENTS.md §6). */
	const uiNotify = (
		ctx: ExtensionContext,
		message: string,
		type: "info" | "warning" | "error" = "info",
	): void => {
		if (ctx.hasUI) ctx.ui.notify(message, type);
	};

	const saveState = () => {
		pi.appendEntry(CONFIG_ENTRY_TYPE, {
			features: { ...features },
		});
	};

	const restoreState = (ctx: ExtensionContext) => {
		let latest: { features?: Partial<typeof features> } | undefined;
		for (const entry of ctx.sessionManager.getEntries()) {
			if (
				entry.type === "custom" &&
				(entry as { customType?: string }).customType === CONFIG_ENTRY_TYPE &&
				entry.data &&
				typeof entry.data === "object"
			) {
				latest = entry.data as typeof latest;
			}
		}
		if (latest?.features) {
			Object.assign(features, latest.features);
		}
	};

	pi.on("session_start", async (_event, ctx) => {
		loadDictionary(ctx.cwd);
		restoreState(ctx);
		refreshStatus(ctx);
	});

	// 1. Ochrana souboru a obousmerny de-anonymizer pred spustenim toolu
	pi.on("tool_call", async (event, ctx) => {
		if (!features.enabled) return;

		// Kontrola chranenych souboru (.env, klice) pro nastroje pracujici se soubory
		if (
			event.toolName === "read" ||
			event.toolName === "write" ||
			event.toolName === "edit" ||
			event.toolName === "read_all"
		) {
			const targetPath = String((event.input as { path?: string })?.path ?? "");
			if (features.block && targetPath && isProtectedPath(targetPath)) {
				if (features.log) {
					uiNotify(ctx, 
						`[anonymizer] BLOKOVAN pristup k chranenemu souboru: ${targetPath}`,
						"warning",
					);
				}
				return {
					block: true,
					reason: `pi-anonymizer: Pristup k chranenemu souboru "${targetPath}" (.env / klice) je striktne zakazan.`,
				};
			}
		}

		// Kontrola allowlistu pro "read"
		if (isToolCallEventType("read", event)) {
			const path = String(event.input.path ?? "");
			if (features.log) uiNotify(ctx, `[anonymizer] read -> ${path}`, "info");

			if (features.block && !isAllowedPath(path)) {
				if (features.log) {
					uiNotify(ctx, `[anonymizer] BLOCKED (mimo allowlist): ${path}`, "warning");
				}
				return {
					block: true,
					reason: `pi-anonymizer: cesta "${path}" neni na allowlistu (${allowedRoots.join("; ")})`,
				};
			}
			return;
		}

		// Obousmerna de-anonymizace (unmask) pred provedenim zmen:
		// Pokud model pouzil __ANON_N__, vratime zpet skutecnou hodnotu
		if (event.toolName === "write") {
			const input = event.input as { path?: string; content?: string };
			if (input && typeof input.content === "string") {
				input.content = unmaskText(input.content);
			}
		}

		if (event.toolName === "edit") {
			const input = event.input as {
				path?: string;
				edits?: Array<{ oldText?: string; newText?: string }>;
			};
			if (input && Array.isArray(input.edits)) {
				for (const ed of input.edits) {
					if (typeof ed.oldText === "string") ed.oldText = unmaskText(ed.oldText);
					if (typeof ed.newText === "string") ed.newText = unmaskText(ed.newText);
				}
			}
		}

		if (isToolCallEventType("bash", event)) {
			const cmd = String(event.input.command ?? "");
			if (features.block && isBashProtected(cmd)) {
				if (features.log) {
					uiNotify(ctx, 
						`[anonymizer] BLOKOVAN bash prikaz (pristup k .env/klicum): ${cmd.slice(0, 60)}`,
						"warning",
					);
				}
				return {
					block: true,
					reason:
						"pi-anonymizer: Shell prikazy pristupujici k .env nebo klicum jsou striktne zakazany.",
				};
			}

			if (typeof event.input.command === "string") {
				event.input.command = unmaskText(event.input.command);
			}
			if (features.log) {
				uiNotify(ctx, `[anonymizer] bash -> ${cmd.slice(0, 80)}`, "info");
			}
		}
	});

	// 2. Anonymizace vysledku pred odeslanim do kontextu modelu
	pi.on("tool_result", async (event, ctx) => {
		if (!features.enabled || !features.redact) return;
		if (event.isError) return;
		if (event.toolName !== "read" && event.toolName !== "bash") return;

		let changed = false;
		const content = event.content.map((item) => {
			if (item.type !== "text") return item;
			const { masked, changed: itemChanged } = maskText(item.text);
			if (itemChanged) changed = true;
			return { ...item, text: masked };
		});

		if (changed) {
			if (features.log) {
				uiNotify(ctx, 
					`[anonymizer] obsah z "${event.toolName}" pseudonymizovan (aktivni tokeny: ${vault.size})`,
					"info",
				);
			}
			refreshStatus(ctx);
			return { content };
		}
	});

	// 3. Slash command /anonymizer
	const TOGGLES = ["log", "block", "redact"];

	pi.registerCommand("anonymizer", {
		description:
			"pi-anonymizer: allowlist, chranene cesty, slovnik tajnosti a obousmerna pseudonymizace",
		getArgumentCompletions: (prefix: string) => {
			const tokens = prefix.split(/\s+/).filter(Boolean);
			const trailingSpace = /\s$/.test(prefix);
			const normalizedPrefix = tokens.join(" ").toLowerCase();

			if (tokens.length > 1 || (trailingSpace && tokens.length === 1)) {
				const cmd = tokens[0].toLowerCase();
				if (TOGGLES.includes(cmd)) {
					const items = ["on", "off"].map((v) => ({
						value: `${cmd} ${v}`,
						label: `${cmd} ${v}`,
						description:
							v === "on"
								? `zapne: ${TOGGLE_DOCS[cmd] ?? cmd}`
								: `vypne: ${TOGGLE_DOCS[cmd] ?? cmd}`,
					}));
					return items.filter((i) =>
						i.value.toLowerCase().startsWith(normalizedPrefix),
					);
				}
				return null;
			}

			const typed = (tokens[0] ?? "").toLowerCase();
			const NON_TERMINAL = new Set(["add", "encrypt", ...TOGGLES]);
			const SUBS: Array<[string, string]> = [
				["on", "HLAVNI VYPINAC — zapne plugin a vsechny ochrany"],
				["off", "HLAVNI VYPINAC — vypne cely plugin"],
				["status", "zobrazi aktualni stav, slovnik a napovedu"],
				["help", "zobrazi podrobnou napovedu k prikazum"],
				["reload", "znovu nacte slovnik z .env a promennych prostredi"],
				["add", "prida povoleny koren adresar do allowlistu"],
				[
					"encrypt",
					"pomocny nastroj: /anonymizer encrypt <heslo> <text> pro vlozeni do .env",
				],
				...TOGGLES.map(
					(t) => [t, TOGGLE_DOCS[t] ?? `prepinac ${t}`] as [string, string],
				),
			];
			const items: AutocompleteItem[] = [];
			for (const [s, description] of SUBS) {
				if (s.toLowerCase().startsWith(typed)) {
					items.push({
						value: NON_TERMINAL.has(s) ? `${s} ` : s,
						label: s,
						description,
					});
				}
			}
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const [subRaw, ...rest] = args.trim().split(/\s+/).filter(Boolean);
			const sub = subRaw?.toLowerCase();

			if ((sub === "on" || sub === "off") && rest.length === 0) {
				const val = sub === "on";
				features.enabled = val;
				features.log = val;
				features.block = val;
				features.redact = val;
				uiNotify(ctx, 
					`[anonymizer] plugin ${val ? "ZAPNUT" : "VYPNUT"}`,
					val ? "info" : "warning",
				);
				refreshStatus(ctx);
				saveState();
				return;
			}

			if (sub === "reload") {
				const { count, sources } = loadDictionary(ctx.cwd);
				uiNotify(ctx, 
					`[anonymizer] slovnik znovu nacten: ${count} polozek (zdroje: ${sources.join(", ") || "zadne"})`,
					"info",
				);
				refreshStatus(ctx);
				return;
			}

			if (sub === "add" && rest.length > 0) {
				const p = resolve(rest.join(" "));
				if (!allowedRoots.includes(p)) allowedRoots.push(p);
				uiNotify(ctx, `[anonymizer] pridan povoleny koren: ${p}`, "info");
				refreshStatus(ctx);
				return;
			}

			// /anonymizer encrypt <passphrase> <text...>
			if (sub === "encrypt") {
				const passphrase = rest[0];
				const plain = rest.slice(1).join(" ");
				if (!passphrase || !plain) {
					uiNotify(ctx, 
						"Pouziti: /anonymizer encrypt <heslo_pro_desifrovani> <tajne_udaje_oddelene_strednikem>",
						"warning",
					);
					return;
				}
				const cipher = encryptSecrets(plain, passphrase);
				uiNotify(ctx, 
					`Zasifrovano! Pridejte do sveho .env:\nPI_ANONYMIZER_KEY="${passphrase}"\nPI_ANONYMIZER_WORDS_ENCRYPTED="${cipher}"`,
					"info",
				);
				return;
			}

			if (sub && TOGGLES.includes(sub)) {
				const key = sub as "log" | "block" | "redact";
				const val = rest[0]?.toLowerCase();
				features[key] =
					val === "on" ? true : val === "off" ? false : !features[key];
				if (features[key]) features.enabled = true;
				uiNotify(ctx, 
					`[anonymizer] ${key} = ${features[key] ? "ON" : "OFF"}`,
					"info",
				);
				refreshStatus(ctx);
				saveState();
				return;
			}

			// help / status
			uiNotify(ctx, 
				[
					`pi-anonymizer — stav: ${features.enabled ? "ZAPNUTO (ON)" : "VYPNUTO (OFF)"}`,
					"Obousmerna pseudonymizace (__ANON_N__) hesel, klicu a slovniku ze zasifrovaneho .env. Blokovani pristupu k .env a klicum.",
					"",
					"Prikazy:",
					"/anonymizer             — tato napoveda + stav",
					"/anonymizer on|off      — HLAVNI VYPINAC",
					"/anonymizer reload      — znovu nacte slovnik z .env a env promennych",
					"/anonymizer add <cesta> — prida povoleny koren allowlistu",
					"/anonymizer encrypt <klic> <text> — zasifruje tajnosti pro .env",
					"/anonymizer <prepinac> [on|off] — prepne konkretni funkci",
					"",
					`Prepinace: log=${features.log ? "ON" : "OFF"} block=${features.block ? "ON" : "OFF"} redact=${features.redact ? "ON" : "OFF"}`,
					...TOGGLES.map((t) => `  ${t.padEnd(7)}— ${TOGGLE_DOCS[t] ?? ""}`),
					"",
					`Slovnik: ${dictionary.size} polozek aktivnich`,
					`Aktivni tokeny: ${vault.size} mapovanych tajnosti`,
					`Allowlist (${allowedRoots.length}): ${allowedRoots.join(";")}`,
					"Chranene soubory: .env*, *.pem, *.key, id_rsa, id_ed25519 (cteni i zapis zablokovany)",
				].join("\n"),
				"info",
			);
		},
	});
}
