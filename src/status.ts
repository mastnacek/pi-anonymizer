/**
 * Feature toggles, their documentation, and the status-line refresher.
 * Split out of `index.ts`.
 */
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { dictionary } from "./dictionary.ts";
import { vault } from "./vault.ts";

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

export const refreshStatus = (ctx: ExtensionContext) => {
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
