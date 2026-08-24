// pi-anonymizer — proof of principle
//
// 1. tool_call("read")  -> zjistime, JAKY soubor si agent chce precist,
//    zalogujeme to a vcas zastavime (block), pokud je mimo povolene cesty.
// 2. tool_result        -> anonymizujeme obsah (hesla/klice/tokeny) driv,
//    nez se dostane do kontextu modelu.
//
// Spusteni: pi -e ./index.ts
// Ovladani: /anonymizer — napoveda a prepinace pro testovani

import { isAbsolute, join, resolve, sep } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";

// --- konfigurace -----------------------------------------------------------

/** Povolene korenove adresare pro cteni. Oddelovac ";" kvuli Windows cestam.
 *  Mutabilni — /anonymizer add <cesta> prida dalsi koren pro toto sezeni. */
const allowedRoots: string[] = (
	process.env.PI_ANONYMIZER_ALLOW ?? process.cwd()
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
const features = {
	log: true, // logovat kazdy read/bash do UI
	block: true, // blokovat read mimo allowlist
	dialog: true, // modalni dialog pri nalezu citlivych udaju (off = automaticka anonymizace)
	redact: true, // anonymizace obsahu (off = data jdou modelu nezredigovana!)
	localai: false, // druha vrstva: lokalni LLM (Ollama/LM Studio) jako dodatecna detekce
};

/** Nastaveni lokalniho AI serveru — OpenAI-kompatibilni API (Ollama default). */
const settings = {
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

export default function (pi: ExtensionAPI) {
	// 1) Detekce + pripadne zastaveni cteni souboru
	pi.on("tool_call", async (event, ctx) => {
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
					ctx.ui.notify(
						"[anonymizer] local-ai probehl, nenasel nic navic",
						"info",
					);
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
	pi.registerCommand("anonymizer", {
		description:
			"pi-anonymizer: napoveda, allowlist, prepinace log/block/dialog/redact",
		handler: async (args, ctx) => {
			const [sub, ...rest] = args.trim().split(/\s+/).filter(Boolean);

			if (sub === "add" && rest.length > 0) {
				const p = resolve(rest.join(" "));
				if (!allowedRoots.includes(p)) allowedRoots.push(p);
				ctx.ui.notify(`[anonymizer] pridan povoleny koren: ${p}`, "info");
				return;
			}

			// /anonymizer aimodel <nazev> — vyber lokalniho modelu
			if (sub === "aimodel") {
				if (!settings.aiModel && rest.length > 0) features.localai = true;
				settings.aiModel = rest.join("-");
				ctx.ui.notify(
					`[anonymizer] aiModel = "${settings.aiModel}"${rest.length > 0 ? " (localai zapnut automaticky)" : ""}`,
					"info",
				);
				return;
			}

			// /anonymizer aiurl <url> — endpoint OpenAI-kompatibilniho serveru
			if (sub === "aiurl") {
				settings.aiUrl = rest[0] ?? settings.aiUrl;
				ctx.ui.notify(`[anonymizer] aiUrl = ${settings.aiUrl}`, "info");
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

			// /anonymizer <log|block|dialog|redact> [on|off]
			if (sub && sub in features) {
				const key = sub as keyof typeof features;
				const val = rest[0]?.toLowerCase();
				features[key] =
					val === "on" ? true : val === "off" ? false : !features[key];
				ctx.ui.notify(
					`[anonymizer] ${key} = ${features[key] ? "ON" : "OFF"}`,
					"info",
				);
				return;
			}

			// help / stav — jedna notifikace, protoze notify prepisuje predchozi zpravu
			ctx.ui.notify(
				[
					"pi-anonymizer — anonymizuje hesla/klice/tokeny, nez se obsah dostane do kontextu modelu; blokuje read mimo allowlist",
					"",
					"/anonymizer             — tato napoveda + stav",
					"/anonymizer add <cesta> — prida povoleny koren (plati do konce sezeni)",
					"/anonymizer <prepinac> [on|off] — prepne (bez argumentu toggle)",
					"/anonymizer aimodel <nazev>  — vyber lokalniho modelu (zapne localai)",
					"/anonymizer aiurl <url>      — endpoint (default Ollama localhost:11434/v1)",
					"/anonymizer models           — vypis modelu z lokalniho serveru",
					"",
					`Prepinace: log=${features.log ? "ON" : "OFF"} block=${features.block ? "ON" : "OFF"} dialog=${features.dialog ? "ON" : "OFF"} redact=${features.redact ? "ON" : "OFF"}`,
					"  log    — notifikace o kazdem read/bash",
					"  block  — blokovani read mimo allowlist",
					"  dialog — dotaz pri nalezu citlivych udaju (OFF = automaticka anonymizace)",
					"  redact — anonymizace obsahu (OFF POZOR: data jdou modelu nestredena!)",
					"  localai— druha vrstva pres lokalni LLM (chytne i to, co regexy neumi)",
					"",
					`LocalAI: url=${settings.aiUrl} model=${settings.aiModel || "(nenastaven!)"}`,
					"",
					`Allowlist (${allowedRoots.length}): ${allowedRoots.join(";")}`,
					'Trvalé nastaveni: env PI_ANONYMIZER_ALLOW="cesta1;cesta2"',
				].join("\n"),
				"info",
			);
		},
	});
}
