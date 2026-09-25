/**
 * AES-256-GCM encryption for the secrets dictionary.
 * Split out of `index.ts`; output format is `ivHex:authTagHex:cipherHex`.
 */
import {
	createCipheriv,
	createDecipheriv,
	randomBytes,
	scryptSync,
} from "node:crypto";

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
