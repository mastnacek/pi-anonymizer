// pi-anonymizer
//
// 1. tool_call   -> Zastavi cteni/zapis chranenych souboru (.env, klice) a cesty mimo allowlist.
//                   Obousmerne de-anonymizuje (unmask) argumenty pro write/edit/bash pred vykonanim.
// 2. tool_result -> Pseudonymizuje citlivy obsah (slovnik ze zasifrovaneho .env + regexy)
//                   pomoci reverzibilnich tokenu __ANON_N__, nez dorazi do kontextu modelu.
//

import { resolve } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import type { AutocompleteItem } from "@earendil-works/pi-tui";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { encryptSecrets } from "./src/crypto.ts";
import { isProtectedPath, isBashProtected, allowedRoots, isAllowedPath } from "./src/protection.ts";
import { dictionary, loadDictionary } from "./src/dictionary.ts";
import { vault, maskText, unmaskText } from "./src/vault.ts";
import { features, TOGGLE_DOCS, refreshStatus } from "./src/status.ts";

// Re-exported so existing importers (including index.test.ts) keep working.
export { encryptSecrets, decryptSecrets } from "./src/crypto.ts";
export { isProtectedPath, isBashProtected, parseDotenv, allowedRoots, isAllowedPath } from "./src/protection.ts";
export { dictionary, loadDictionary } from "./src/dictionary.ts";
export { vault, maskText, anonymizeText, unmaskText } from "./src/vault.ts";
export { features, TOGGLE_DOCS } from "./src/status.ts";

export default function (pi: ExtensionAPI) {
	/** Unsubscribers from every `pi.on()`; drained on session_shutdown (AGENTS §5). */
	const unsubscribers: Array<() => void> = [];

	/** Retain a `pi.on()` return value; older engine typings declare it void. */
	const track = (result: unknown): void => {
		if (typeof result === "function") unsubscribers.push(result as () => void);
	};

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

	track(pi.on("session_start", async (_event, ctx) => {
		loadDictionary(ctx.cwd);
		restoreState(ctx);
		refreshStatus(ctx);
	}));

	// 1. Ochrana souboru a obousmerny de-anonymizer pred spustenim toolu
	track(pi.on("tool_call", async (event, ctx) => {
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
	}));

	// 2. Anonymizace vysledku pred odeslanim do kontextu modelu
	track(pi.on("tool_result", async (event, ctx) => {
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
	}));

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

	pi.on("session_shutdown", () => {
		while (unsubscribers.length > 0) unsubscribers.pop()?.();
	});
}
