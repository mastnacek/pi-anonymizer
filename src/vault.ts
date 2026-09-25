/**
 * Reversible pseudonymisation: the `__ANON_N__` token vault, the regex layer and
 * the mask/unmask entry points.
 * Split out of `index.ts`.
 */
import { dictionary } from "./dictionary.ts";

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
