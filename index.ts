// pi-anonymizer — proof of principle
//
// 1. tool_call("read")  -> zjistime, JAKY soubor si agent chce precist,
//    zalogujeme to a vcas zastavime (block), pokud je mimo povolene cesty.
// 2. tool_result        -> anonymizujeme obsah (hesla/klice/tokeny) driv,
//    nez se dostane do kontextu modelu.
//
// Spusteni: pi -e ./index.ts
// Ovladani: /anonymizer — napoveda a prepinace pro testovani

import { tmpdir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import type {
	ExtensionAPI,
	ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

// --- konfigurace -----------------------------------------------------------

/** Povolene korenove adresare pro cteni. Oddelovac ";" kvuli Windows cestam.
 *  Implicitne cwd + tmpdir (pro clipboard obrazky a docasne soubory pi).
 *  Mutabilni — /anonymizer add <cesta> prida dalsi koren pro toto sezeni. */
const defaultRoots = [process.cwd(), tmpdir()];
const allowedRoots: string[] = (
	process.env.PI_ANONYMIZER_ALLOW ?? defaultRoots.join(";")
)
	.split(";")
	.map((p) => p.trim())
	.filter(Boolean);

const isAllowedPath = (path: string): boolean => {
	const abs = isAbsolute(path)
		? resolve(path)
		: resolve(join(process.cwd(), path));
	return allowedRoots.some((root) => {
		const r = resolve(root);
		return abs === r || abs.startsWith(r + sep);
	});
};

/** Prepinace pro testovani — /anonymizer <jmeno> on|off (plati do restartu pi). */
export const features = {
	enabled: true, // hlavni master switch (off = plugin zcela neaktivni)
	log: true, // logovat kazdy read/bash do UI
	block: true, // blokovat read mimo allowlist
	dialog: true, // modalni dialog pri nalezu citlivych udaju (off = automaticka anonymizace)
	redact: true, // anonymizace obsahu (off = data jdou modelu nezredigovana!)
	localai: false, // druha vrstva: lokalni LLM (Ollama/LM Studio) jako dodatecna detekce
};

/** Popisy prepinacu — jediny zdroj pro autocomplete i napovedu. */
export const TOGGLE_DOCS: Record<string, string> = {
	log: "notifikace o kazdem read/bash volani v UI",
	block: "zablokuje cteni souboru mimo allowlist",
	dialog:
		"modalni dotaz pri nalezu citlivych udaju (OFF = automaticka anonymizace)",
	redact:
		"regex anonymizace hesel/klicu/tokenu (OFF POZOR: data jdou modelu neošetrena!)",
	localai:
		"druha vrstva pres lokalni LLM — chytne i uzivatelska jmena a emaily, ktere regexy neumi",
};

/** Nastaveni lokalniho AI serveru — OpenAI-kompatibilni API (Ollama default). */
export const settings = {
	aiUrl: process.env.PI_ANONYMIZER_LOCALAI_URL ?? "http://localhost:11434/v1",
	aiModel: process.env.PI_ANONYMIZER_LOCALAI_MODEL ?? "",
};

const SANITIZE_PROMPT =
	"You sanitize source code and config text before it is sent to another AI. " +
	"Replace every username, password, secret, token, API key, connection string, " +
	"email address and personal name with [REDACTED]. Keep everything else exactly as is. " +
	"Return ONLY the sanitized text, no commentary.";

/** Druha anonymizacni vrstva pres lokalni LLM. Vraci null pri chybe/timeoutu. */
export const anonymizeWithLocalAI = async (
	text: string,
	signal?: AbortSignal,
): Promise<string | null> => {
	if (!settings.aiModel || !features.localai) return null;
	try {
		const res = await fetch(`${settings.aiUrl}/chat/completions`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				model: settings.aiModel,
				messages: [
					{ role: "system", content: SANITIZE_PROMPT },
					{ role: "user", content: text },
				],
				temperature: 0,
			}),
			signal: signal
				? AbortSignal.any([signal, AbortSignal.timeout(120_000)])
				: AbortSignal.timeout(120_000),
		});
		if (!res.ok) return null;
		const data = (await res.json()) as {
			choices?: Array<{ message?: { content?: string } }>;
		};
		return data.choices?.[0]?.message?.content ?? null;
	} catch {
		return null;
	}
};

const REDACTED = "[REDACTED]";

export const anonymizeText = (text: string): string =>
	text
		// klicova slova typu heslo/token/klic nasledovana dvojteckou nebo rovnitkem
		// (?<![a-zA-Z0-9]) misto \b — aby chytilo i database_password, auth_token apod. (podtrzitko neni hranice slova)
		.replace(
			/(?<![a-zA-Z0-9])(pass(word|wd)?|pwd|secret|token|api[-_]?key|auth)(\s*[:=]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[A-Za-z0-9_\-./+]{8,})/gi,
			(_m, keyword, _inner, sep) => `${keyword}${sep}"${REDACTED}"`,
		)
		// dlouhe hexadecimalni retezce (typicky klice)
		.replace(/\b[0-9a-fA-F]{32,}\b/g, REDACTED);

// --- extension -------------------------------------------------------------

/** Krátky status pro statusline (eldritch-footer zobrazí ctx.ui.setStatus). */
const refreshStatus = (ctx: ExtensionContext) => {
	if (!features.enabled) {
		ctx.ui.setStatus("anonymizer", "anon off");
		return;
	}
	ctx.ui.setStatus(
		"anonymizer",
		`anon ${features.redact ? "R" : "·"}${features.block ? "B" : "·"}${features.dialog ? "D" : "·"} · ${
			settings.aiModel ? `ai:${settings.aiModel}` : "ai off"
		}`, // napr. "anon RBD · ai:ornith-9b"
	);
};

export default function (pi: ExtensionAPI) {
	// Perzistence nastaveni do session logu (prezije /reload, /resume, restart
	// se stejnym session souborem) — vzor eldritch-footer.
	const CONFIG_ENTRY_TYPE = "pi-anonymizer-config";

	const saveState = () => {
		pi.appendEntry(CONFIG_ENTRY_TYPE, {
			features: { ...features },
			aiModel: settings.aiModel,
			aiUrl: settings.aiUrl,
		});
	};

	const restoreState = (ctx: ExtensionContext) => {
		let latest:
			| { features?: Partial<typeof features>; aiModel?: string; aiUrl?: string }
			| undefined;
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
		if (!latest) return;
		if (latest.features) Object.assign(features, latest.features);
		if (latest.aiModel !== undefined) settings.aiModel = latest.aiModel;
		if (latest.aiUrl !== undefined) settings.aiUrl = latest.aiUrl;
	};

	pi.on("session_start", async (_event, ctx) => {
		restoreState(ctx);
		refreshStatus(ctx);
	});

	// 1) Detekce + pripadne zastaveni cteni souboru
	pi.on("tool_call", async (event, ctx) => {
		if (!features.enabled) return;
		if (isToolCallEventType("read", event)) {
			const path = String(event.input.path ?? "");
			if (features.log) ctx.ui.notify(`[anonymizer] read -> ${path}`, "info");

			if (!features.block) return;
			if (!isAllowedPath(path)) {
				if (features.log)
					ctx.ui.notify(`[anonymizer] BLOCKED (mimo allowlist): ${path}`, "warning");
				return {
					block: true,
					reason: `pi-anonymizer: cesta "${path}" neni na allowlistu (${allowedRoots.join("; ")})`,
				};
			}
			return;
		}

		// bash jen logujeme — obsah stejne projde anonymizaci v tool_result,
		// blokovani by delalo false positive u legitimnich prikazu (grep/head nad cizimi cestami)
		if (features.log && isToolCallEventType("bash", event)) {
			ctx.ui.notify(
				`[anonymizer] bash -> ${String(event.input.command ?? "").slice(0, 80)}`,
				"info",
			);
		}
	});

	// 2) Anonymizace vysledku, nez jde do kontextu modelu
	pi.on("tool_result", async (event, ctx) => {
		if (!features.enabled) return;
		if (event.isError) return;
		if (event.toolName !== "read" && event.toolName !== "bash") return;
		if (!features.redact && !features.dialog) return;

		let changed = false;
		const content = event.content.map((item) => {
			if (item.type !== "text") return item;
			const redacted = features.redact ? anonymizeText(item.text) : item.text;
			if (redacted !== item.text) changed = true;
			return { ...item, text: redacted };
		});

		// druha vrstva — lokalni LLM jako dodatecna detekce nad regex-redigovanym textem
		if (features.localai && settings.aiModel) {
			for (const item of content) {
				if (item.type !== "text") continue;
				ctx.ui.setStatus("anonymizer", `local-ai scan (${settings.aiModel})...`);
				const ai = await anonymizeWithLocalAI(item.text, ctx.signal);
				ctx.ui.setStatus("anonymizer", undefined);
				if (ai === null) {
					if (features.log)
						ctx.ui.notify(
							`[anonymizer] local-ai volani SELHALO (model "${settings.aiModel}" na ${settings.aiUrl}) — pokracuji jen s regexy`,
							"warning",
						);
				} else if (ai !== item.text) {
					item.text = ai;
					changed = true;
					if (features.log)
						ctx.ui.notify("[anonymizer] local-ai doplnil dalsi redakce", "info");
				} else if (features.log) {
					ctx.ui.notify("[anonymizer] local-ai probehl, nenasel nic navic", "info");
				}
			}
		}

		if (!changed) return { content };

		// V TUI se zeptame uzivatele, co s nalezem; v print mode anonymizujeme automaticky.
		if (ctx.hasUI && features.dialog) {
			const choice = await ctx.ui.select(
				"⚠ pi-anonymizer: nalezeny citlive udaje",
				[
					`Anonymizovat (default)`,
					"Bloknout — model obsah neuvidi vubec",
					"Pustit beze zmeny",
				],
			);
			if (choice?.startsWith("Bloknout")) {
				ctx.ui.notify(
					`[anonymizer] cteni zablokovano po nalezu citlivych udaju`,
					"warning",
				);
				return {
					content: [
						{
							type: "text",
							text:
								"[pi-anonymizer] Obsah zablokovan — byl v nem detekovan citlivy udaj.",
						},
					],
					isError: true,
				};
			}
			if (choice === null) {
				// dialog zrusen (Esc) -> bezpecna default akce
				return { content };
			}
			if (choice?.startsWith("Pustit")) {
				ctx.ui.notify(
					"[anonymizer] obsazeni pusten BEZE ZMEN na uzivatelovo zadost",
					"warning",
				);
				return;
			}
		}

		if (features.log)
			ctx.ui.notify(
				`[anonymizer] obsah z "${event.toolName}" anonymizovan`,
				"warning",
			);
		return { content };
	});

	// 3) /anonymizer — napoveda, allowlist a prepinace pro bezici sezeni
	const TOGGLES = ["log", "block", "dialog", "redact", "localai"];

	pi.registerCommand("anonymizer", {
		description:
			"pi-anonymizer: napoveda, allowlist, prepinace log/block/dialog/redact/localai, lokalni AI",
		// Lazy autocomplete: pri psani /anonymizer <prefix> navrhne podprikazy,
		// u prepinacu pak i on/off.
		getArgumentCompletions: (prefix: string) => {
			const tokens = prefix.split(/\s+/).filter(Boolean);
			const trailingSpace = /\s$/.test(prefix);
			const normalizedPrefix = tokens.join(" ").toLowerCase();

			// druhe slovo — jen u prepinacu nabizime on/off
			if (tokens.length > 1 || (trailingSpace && tokens.length === 1)) {
				const cmd = tokens[0].toLowerCase();
				if (!TOGGLES.includes(cmd)) return null; // add/aimodel/aiurl = volny text
				const items = ["on", "off"].map((v) => ({
					value: `${cmd} ${v}`,
					label: `${cmd} ${v}`,
					description:
						v === "on"
							? `zapne: ${TOGGLE_DOCS[cmd] ?? cmd}`
							: `vypne: ${TOGGLE_DOCS[cmd] ?? cmd}`,
				}));
				const filtered = items.filter((i) =>
					i.value.toLowerCase().startsWith(normalizedPrefix),
				);
				return filtered.length > 0 ? filtered : null;
			}

			// prvni slovo — podprikazy
			const typed = (tokens[0] ?? "").toLowerCase();
			const SUBS: Array<[string, string]> = [
				["on", "HLAVNI VYPINAC — zapne cely plugin a vsechny funkce najednou"],
				[
					"off",
					"HLAVNI VYPINAC — vypne cely plugin (zadne blokovani, dialogy ani redakce)",
				],
				["status", "zobrazi aktualni stav a napovedu pluginu"],
				["help", "zobrazi podrobnou napovedu k prikazum"],
				[
					"add",
					"prida povoleny koren adresar do allowlistu (plati do restartu pi)",
				],
				[
					"aimodel",
					"vyber lokalniho LLM modelu pro druhou anonymizacni vrstvu (automaticky zapne localai)",
				],
				[
					"aiurl",
					"adresa OpenAI-kompatibilniho serveru (Ollama, LM Studio, llama.cpp)",
				],
				["models", "vypise modely nainstalovane na lokalnim serveru"],
				...TOGGLES.map(
					(t) => [t, TOGGLE_DOCS[t] ?? `prepinac ${t}`] as [string, string],
				),
			];
			const items = SUBS.filter(([s]) => s.toLowerCase().startsWith(typed)).map(
				([value, description]) => ({ value, label: value, description }),
			);
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const [subRaw, ...rest] = args.trim().split(/\s+/).filter(Boolean);
			const sub = subRaw?.toLowerCase();

			// /anonymizer on|off — hlavni vypinac vsech funkci najednou
			if ((sub === "on" || sub === "off") && rest.length === 0) {
				const val = sub === "on";
				features.enabled = val;
				features.log = val;
				features.block = val;
				features.dialog = val;
				features.redact = val;
				if (!val) features.localai = false;
				ctx.ui.notify(
					`[anonymizer] plugin ${val ? "ZAPNUT (vsechny funkce aktivni)" : "VYPNUT (vsechny funkce deaktivovany)"}`,
					val ? "info" : "warning",
				);
				refreshStatus(ctx);
				saveState();
				return;
			}

			if (sub === "add" && rest.length > 0) {
				const p = resolve(rest.join(" "));
				if (!allowedRoots.includes(p)) allowedRoots.push(p);
				ctx.ui.notify(`[anonymizer] pridan povoleny koren: ${p}`, "info");
				refreshStatus(ctx);
				saveState();
				return;
			}

			// /anonymizer aimodel <nazev> — vyber lokalniho modelu
			if (sub === "aimodel") {
				if (!settings.aiModel && rest.length > 0) {
					features.enabled = true;
					features.localai = true;
				}
				settings.aiModel = rest.join("-");
				ctx.ui.notify(
					`[anonymizer] aiModel = "${settings.aiModel}"${rest.length > 0 ? " (localai zapnut automaticky)" : ""}`,
					"info",
				);
				refreshStatus(ctx);
				saveState();
				return;
			}

			// /anonymizer aiurl <url> — endpoint OpenAI-kompatibilniho serveru
			if (sub === "aiurl") {
				settings.aiUrl = rest[0] ?? settings.aiUrl;
				ctx.ui.notify(`[anonymizer] aiUrl = ${settings.aiUrl}`, "info");
				refreshStatus(ctx);
				saveState();
				return;
			}

			// /anonymizer models — vypis modelu z lokalniho serveru
			if (sub === "models") {
				try {
					const res = await fetch(`${settings.aiUrl}/models`, {
						signal: AbortSignal.timeout(5000),
					});
					const data = (await res.json()) as {
						data?: Array<{ id?: string }>;
					};
					const ids = data.data?.map((m) => m.id ?? "?") ?? [];
					ctx.ui.notify(
						`[anonymizer] modely na ${settings.aiUrl}:\n${ids.join("\n") || "(zadne)"}\nNastaveni: /anonymizer aimodel <nazev>`,
						"info",
					);
				} catch {
					ctx.ui.notify(
						`[anonymizer] server ${settings.aiUrl} neodpovida — bezi Ollama/LM Studio?`,
						"warning",
					);
				}
				return;
			}

			// /anonymizer <log|block|dialog|redact|localai> [on|off]
			if (sub && TOGGLES.includes(sub)) {
				const key = sub as "log" | "block" | "dialog" | "redact" | "localai";
				const val = rest[0]?.toLowerCase();
				features[key] =
					val === "on" ? true : val === "off" ? false : !features[key];
				if (features[key]) features.enabled = true;
				ctx.ui.notify(
					`[anonymizer] ${key} = ${features[key] ? "ON" : "OFF"}${features.enabled ? "" : " (pozor: plugin je globalne OFF)"}`,
					"info",
				);
				refreshStatus(ctx);
				saveState();
				return;
			}

			// help / stav — jedna notifikace, protoze notify prepisuje predchozi zpravu
			ctx.ui.notify(
				[
					`pi-anonymizer — stav: ${features.enabled ? "ZAPNUTO (ON)" : "VYPNUTO (OFF)"}`,
					"Anonymizuje hesla/klice/tokeny (regex) a uzivatele/jmena (lokalni LLM), nez se obsah dostane do kontextu modelu; blokuje read mimo allowlist.",
					"",
					"Prikazy:",
					"/anonymizer             — tato napoveda + stav",
					"/anonymizer on|off      — HLAVNI VYPINAC: zapne/vypne cely plugin",
					"/anonymizer add <cesta> — prida povoleny koren (do restartu pi)",
					"/anonymizer <prepinac> [on|off] — prepne konkretni funkci",
					"/anonymizer aimodel <nazev>  — vyber lokalniho modelu (zapne localai)",
					"/anonymizer aiurl <url>      — endpoint (default Ollama localhost:11434/v1)",
					"/anonymizer models           — vypis modelu z lokalniho serveru",
					"",
					`Prepinace: log=${features.log ? "ON" : "OFF"} block=${features.block ? "ON" : "OFF"} dialog=${features.dialog ? "ON" : "OFF"} redact=${features.redact ? "ON" : "OFF"} localai=${features.localai ? "ON" : "OFF"}`,
					...TOGGLES.map((t) => `  ${t.padEnd(7)}— ${TOGGLE_DOCS[t] ?? ""}`),
					"",
					`LocalAI: url=${settings.aiUrl} model=${settings.aiModel || "(nenastaven!)"}`,
					"",
					`Allowlist (${allowedRoots.length}): ${allowedRoots.join(";")}`,
					'Trvalé nastaveni: env PI_ANONYMIZER_ALLOW="cesta1;cesta2" PI_ANONYMIZER_LOCALAI_MODEL="model"',
					"Zmeny se ukladaji do session — preziji /reload i /resume.",
				].join("\n"),
				"info",
			);
		},
	});
}
