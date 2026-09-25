/**
 * The secrets dictionary: decrypted `.env` entries plus the terms loaded from
 * the configured word list.
 * Split out of `index.ts`.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { decryptSecrets } from "./crypto.ts";
import { parseDotenv } from "./protection.ts";

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
