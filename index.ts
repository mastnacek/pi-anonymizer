// pi-anonymizer — proof of principle
//
// 1. tool_call("read")  -> zjistime, JAKY soubor si agent chce precist,
//    zalogujeme to a vcas zastavime (block), pokud je mimo povolene cesty.
// 2. tool_result        -> anonymizujeme obsah (hesla/klice/tokeny) driv,
//    nez se dostane do kontextu modelu.
//
// Spusteni: pi -e ./index.ts

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
			ctx.ui.notify(`[anonymizer] read -> ${path}`, "info");

			if (!isAllowedPath(path)) {
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
		if (isToolCallEventType("bash", event)) {
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

		let changed = false;
		const content = event.content.map((item) => {
			if (item.type !== "text") return item;
			const redacted = anonymizeText(item.text);
			if (redacted !== item.text) changed = true;
			return { ...item, text: redacted };
		});

		if (!changed) return { content };

		// V TUI se zeptame uzivatele, co s nalezem; v print mode anonymizujeme automaticky.
		if (ctx.hasUI) {
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

		ctx.ui.notify(
			`[anonymizer] obsah z "${event.toolName}" anonymizovan`,
			"warning",
		);
		return { content };
	});

	// 3) /anonymizer — napoveda + nastaveni allowlistu pro bezici sezeni
	pi.registerCommand("anonymizer", {
		description:
			"pi-anonymizer: napoveda, stav allowlistu, pridani povolene cesty",
		handler: async (args, ctx) => {
			const [sub, ...rest] = args.trim().split(/\s+/).filter(Boolean);

			if (sub === "add" && rest.length > 0) {
				const p = resolve(rest.join(" "));
				if (!allowedRoots.includes(p)) allowedRoots.push(p);
				ctx.ui.notify(`[anonymizer] pridan povoleny koren: ${p}`, "info");
				return;
			}

			// help / stav — jedna notifikace, protoze notify prepisuje predchozi zpravu
			ctx.ui.notify(
				[
					"pi-anonymizer — anonymizuje hesla/klice/tokeny, nez se obsah dostane do kontextu modelu; blokuje read mimo allowlist",
					"",
					"/anonymizer             — tato napoveda",
					"/anonymizer add <cesta> — prida povoleny koren (plati do konce sezeni)",
					"",
					`Allowlist (${allowedRoots.length}): ${allowedRoots.join(";")}`,
					'Trvalé nastaveni: env PI_ANONYMIZER_ALLOW="cesta1;cesta2"',
				].join("\n"),
				"info",
			);
		},
	});
}
