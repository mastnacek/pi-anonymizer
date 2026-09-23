// Testy pi-anonymizeru — spusteni: npm test
// Kryje regexovou vrstvu, slovnik tajnosti, AES-256-GCM kryptografii,
// obousmernou pseudonymizaci (unmask) a ochranu souboru.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
	anonymizeText,
	maskText,
	unmaskText,
	encryptSecrets,
	decryptSecrets,
	loadDictionary,
	dictionary,
	vault,
	isProtectedPath,
	isBashProtected,
	isAllowedPath,
	features,
} from "./index.ts";

beforeEach(() => {
	features.enabled = true;
	features.redact = true;
	features.block = true;
	dictionary.clear();
	vault.clear();
});

// --- regexova vrstva -------------------------------------------------------

test('regex: rediguje password = "..."', () => {
	const out = anonymizeText('password = "SuperTajneHeslo123"');
	assert.match(out, /password = "__ANON_\d+__"/);
	assert.equal(unmaskText(out), 'password = "SuperTajneHeslo123"');
});

test("regex: chytne podtrzitkove prefixy (database_password)", () => {
	const out = anonymizeText('database_password = "SuperTajneHeslo123"');
	assert.match(out, /database_password = "__ANON_\d+__"/);
	assert.equal(unmaskText(out), 'database_password = "SuperTajneHeslo123"');
});

test("regex: chytne auth_token s JWT", () => {
	const out = anonymizeText("auth_token: 'eyJhbGciOiJIUzI1NiJ9.test.sig'");
	assert.match(out, /auth_token: "__ANON_\d+__"/);
	assert.equal(unmaskText(out), 'auth_token: "eyJhbGciOiJIUzI1NiJ9.test.sig"');
});

test("regex: chytne API_KEY v uvozovkach", () => {
	const out = anonymizeText('API_KEY="sk-test-1234567890abcdef"');
	assert.match(out, /API_KEY="__ANON_\d+__"/);
	assert.equal(unmaskText(out), 'API_KEY="sk-test-1234567890abcdef"');
});

test("regex: chytne token bez uvozovek", () => {
	const out = anonymizeText("token: eyJhbGciOiJIUzI1NiJ9.xxx");
	assert.match(out, /token: __ANON_\d+__/);
	assert.equal(unmaskText(out), "token: eyJhbGciOiJIUzI1NiJ9.xxx");
});

test("regex: chytne dlouhy hex klic", () => {
	const out = anonymizeText("hex 0123456789abcdef0123456789abcdef");
	assert.match(out, /hex __ANON_\d+__/);
	assert.equal(unmaskText(out), "hex 0123456789abcdef0123456789abcdef");
});

test("regex: chytne connection string s heslem", () => {
	const orig = "postgres://admin:TopSecretPass2026@internal-db.corp:5432/main";
	const out = anonymizeText(orig);
	assert.match(
		out,
		/postgres:\/\/admin:__ANON_\d+__@internal-db\.corp:5432\/main/,
	);
	assert.equal(unmaskText(out), orig);
});

test("regex: chytne PEM privatni klic", () => {
	const pem =
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----";
	const out = anonymizeText(pem);
	assert.match(out, /__ANON_\d+__/);
	assert.equal(unmaskText(out), pem);
});

test("regex: neresi necitlive radky", () => {
	const safe = "SELECT * FROM csrj1 WHERE id = 42;";
	assert.equal(anonymizeText(safe), safe);
});

test("regex: kratsi hodnoty nez limit nechava byt", () => {
	assert.equal(anonymizeText('password = "abc"'), 'password = "abc"');
});

// --- slovnik tajnosti a jmen -----------------------------------------------

test("slovnik: maskuje jmena a specificka slova dodana do slovniku", () => {
	dictionary.add("Jan Novak");
	dictionary.add("Karel Vopicka");

	const orig = "Autor: Jan Novak, revidoval Karel Vopicka a Petr Bezruc.";
	const out = anonymizeText(orig);

	assert.doesNotMatch(out, /Jan Novak/);
	assert.doesNotMatch(out, /Karel Vopicka/);
	assert.match(out, /Petr Bezruc/);

	// De-anonymizace vrati puvodni text
	assert.equal(unmaskText(out), orig);
});

test("slovnik: nahrazuje nejdelsi shody prednostne", () => {
	dictionary.add("Jan");
	dictionary.add("Jan Novak");

	const orig = "Jan Novak sel s Janem, ktery je proste Jan.";
	const out = anonymizeText(orig);

	assert.equal(unmaskText(out), orig);
});

// --- krypto vrstva (AES-256-GCM) -------------------------------------------

test("krypto: uspesne zasifruje a desifruje text", () => {
	const secret = "Jan Novak;SuperTajneHeslo99;corp.internal";
	const pass = "silne_heslo_123";

	const encrypted = encryptSecrets(secret, pass);
	assert.notEqual(encrypted, secret);
	assert.match(encrypted, /^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);

	const decrypted = decryptSecrets(encrypted, pass);
	assert.equal(decrypted, secret);
});

test("krypto: spatne heslo vrati null", () => {
	const encrypted = encryptSecrets("tajnost", "spravne_heslo");
	const decrypted = decryptSecrets(encrypted, "spatne_heslo");
	assert.equal(decrypted, null);
});

test("krypto: poskozeny ciphertext vrati null", () => {
	const decrypted = decryptSecrets("invalid:payload:data", "heslo");
	assert.equal(decrypted, null);
});

// --- obousmerna pseudonymizace v praxi (write / edit) ------------------------

test("unmask: simulace agenta upravujiciho kod s tokenem", () => {
	// 1. Soubor nacten a maskovan
	const diskContent = 'const dbPass = "UltraSecretProdPass!";';
	const masked = anonymizeText(diskContent);
	assert.match(masked, /const dbPass = "__ANON_\d+__";/);

	// 2. Agent udela edit: prida k radku komentovany export
	const agentEdit = masked.replace(
		'const dbPass = "',
		'export const dbPass = "',
	);

	// 3. Plugin pred zasahem do disku provede unmask
	const unmaskedBeforeWrite = unmaskText(agentEdit);
	assert.equal(
		unmaskedBeforeWrite,
		'export const dbPass = "UltraSecretProdPass!";',
	);
});

// --- ochrana chranenych souboru a cest -------------------------------------

test("bash ochrana: detekuje prikazy pristupujici k .env a klicum", () => {
	assert.equal(isBashProtected("cat .env"), true);
	assert.equal(isBashProtected("cat .env.local"), true);
	assert.equal(isBashProtected("head -n 10 ./.env"), true);
	assert.equal(isBashProtected("grep SECRET path/.env"), true);
	assert.equal(isBashProtected("type .\\.env"), true);
	assert.equal(isBashProtected("python script.py < .env"), true);
	assert.equal(isBashProtected("cat ~/.ssh/id_rsa"), true);
	assert.equal(isBashProtected("openssl x509 -in cert.pem"), true);

	// Bezpecne prikazy nesmi blokovat
	assert.equal(isBashProtected("npm install dotenv"), false);
	assert.equal(isBashProtected("npm test"), false);
	assert.equal(isBashProtected("git status"), false);
	assert.equal(isBashProtected("echo hello world"), false);
});

test("slovnik: loadDictionary nacita z env promenne PI_ANONYMIZER_WORDS", () => {
	process.env.PI_ANONYMIZER_WORDS = "Karel Gott;SuperHeslo2026";
	const res = loadDictionary();
	assert.ok(res.count >= 2);
	assert.ok(dictionary.has("Karel Gott"));
	assert.ok(dictionary.has("SuperHeslo2026"));
	delete process.env.PI_ANONYMIZER_WORDS;
});

test("slovnik: loadDictionary nacita zasifrovany slovnik z env promennych", () => {
	const secretWords = "TajnyProjektX;Vojtech Dyk";
	const pass = "hesloProEnv123";
	const cipher = encryptSecrets(secretWords, pass);

	process.env.PI_ANONYMIZER_WORDS_ENCRYPTED = cipher;
	process.env.PI_ANONYMIZER_KEY = pass;

	const res = loadDictionary();
	assert.ok(res.count >= 2);
	assert.ok(dictionary.has("TajnyProjektX"));
	assert.ok(dictionary.has("Vojtech Dyk"));

	delete process.env.PI_ANONYMIZER_WORDS_ENCRYPTED;
	delete process.env.PI_ANONYMIZER_KEY;
});

test("regex: chytne AWS, GitHub a Stripe vendor klice", () => {
	const aws = "aws_key = AKIAIOSFODNN7EXAMPLE";
	const gh = "github = ghp_123456789012345678901234567890123456";
	const stripe =
		"stripe = " + ["sk", "test", "fake0123456789abcdef0123456"].join("_");

	assert.match(anonymizeText(aws), /AKIAIOSFODNN7EXAMPLE|__ANON_\d+__/);
	assert.match(anonymizeText(gh), /ghp_|__ANON_\d+__/);
	assert.match(anonymizeText(stripe), /sk_test_|__ANON_\d+__/);

	assert.equal(unmaskText(anonymizeText(aws)), aws);
	assert.equal(unmaskText(anonymizeText(gh)), gh);
	assert.equal(unmaskText(anonymizeText(stripe)), stripe);
});

test("allowlist: overuje cesty v projektu a tmp", () => {
	assert.equal(isAllowedPath(process.cwd()), true);
	assert.equal(isAllowedPath("src/index.ts"), true);
});

test("chranene soubory: blokuje .env a klice", () => {
	assert.equal(isProtectedPath(".env"), true);
	assert.equal(isProtectedPath(".env.local"), true);
	assert.equal(isProtectedPath(".env.production"), true);
	assert.equal(isProtectedPath("C:\\project\\.env"), true);
	assert.equal(isProtectedPath("server.key"), true);
	assert.equal(isProtectedPath("cert.pem"), true);
	assert.equal(isProtectedPath("id_rsa"), true);
	assert.equal(isProtectedPath("id_ed25519"), true);
});

test("chranene soubory: povoluje bezne zdrojove kody", () => {
	assert.equal(isProtectedPath("src/index.ts"), false);
	assert.equal(isProtectedPath("package.json"), false);
	assert.equal(isProtectedPath("README.md"), false);
	assert.equal(isProtectedPath("test-secret.txt"), false);
});
