/**
 * Guards: protected paths, dangerous bash commands, `.env` parsing and the
 * allowlist of roots that tool calls may touch.
 * Split out of `index.ts`.
 */
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";

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
