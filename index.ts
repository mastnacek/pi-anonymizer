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

/** Povolene korenove adresare pro cteni. Oddelovac ";" kvuli Windows cestam. */
const allowedRoots = (): string[] => {
	const raw =
		process.env.PI_ANONYMIZER_ALLOW ?? process.cwd();
	return raw.split(";").map((p) => p.trim()).filter(Boolean);
};

const isAllowedPath = (path: string): boolean => {
	const abs = isAbsolute(path) ? resolve(path) : resolve(join(process.cwd(), path));
	return allowedRoots().some((root) => {
		const r = resolve(root);
		return abs === r || abs.startsWith(r + sep);
	});
};

const REDACTED = "[REDACTED]";

export const anonymizeText = (text: string): string =>
	text
		// klicova slova typu heslo/token/klic nasledovana dvojteckou nebo rovnitkem
		.replace(
			/\b(pass(word|wd)?|pwd|secret|token|api[-_]?key|auth)\b(\s*[:=]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[A-Za-z0-9_\-./+]{8,})/gi,
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
					reason: `pi-anonymizer: cesta "${path}" neni na allowlistu (${allowedRoots().join("; ")})`,
				};
			}
			return;
		}

		// bash zatim jen logujeme — je dalsi kandidat na anonymizaci/blokaci
		if (isToolCallEventType("bash", event)) {
			ctx.ui.notify(`[anonymizer] bash -> ${event.input.command?.slice(0, 80) ?? ""}`, "info");
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

		if (changed) ctx.ui.notify(`[anonymizer] obsah z "${event.toolName}" anonymizovan`, "warning");
		return { content };
	});
}
