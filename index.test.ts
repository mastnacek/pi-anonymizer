// Testy pi-anonymizeru — spusteni: npm test
// Kryje regexovou vrstvu (anonymizeText) a lokalni AI vrstvu
// (anonymizeWithLocalAI s mockovanym fetchem).

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
	anonymizeText,
	anonymizeWithLocalAI,
	features,
	settings,
} from "./index.ts";

const REDACTED = "[REDACTED]";

// --- regexova vrstva -------------------------------------------------------

test("regex: rediguje password = \"...\"", () => {
	assert.equal(
		anonymizeText('password = "SuperTajneHeslo123"'),
		`password = "${REDACTED}"`,
	);
});

test("regex: chytne podtrzitkove prefixy (database_password)", () => {
	// historicky leak z prvniho testu — \b nepovazoval _ za hranici slova
	assert.equal(
		anonymizeText('database_password = "SuperTajneHeslo123"'),
		`database_password = "${REDACTED}"`,
	);
});

test("regex: chytne auth_token s JWT", () => {
	assert.equal(
		anonymizeText("auth_token: 'eyJhbGciOiJIUzI1NiJ9.test.sig'"),
		`auth_token: "${REDACTED}"`,
	);
});

test("regex: chytne API_KEY v uvozovkach", () => {
	assert.equal(
		anonymizeText('API_KEY="sk-test-1234567890abcdef"'),
		`API_KEY="${REDACTED}"`,
	);
});

test("regex: chytne token bez uvozovek", () => {
	assert.equal(
		anonymizeText("token: eyJhbGciOiJIUzI1NiJ9.xxx"),
		`token: "${REDACTED}"`,
	);
});

test("regex: chytne dlouhy hex klic", () => {
	assert.equal(
		anonymizeText("hex 0123456789abcdef0123456789abcdef"),
		`hex ${REDACTED}`,
	);
});

test("regex: neresi necitlive radky", () => {
	const safe = "username = jan.novak\nSELECT * FROM csrj1";
	assert.equal(anonymizeText(safe), safe);
});

test("regex: kratsi hodnoty nez limit nechava byt", () => {
	// quoted hodnota musi mit 4+ znaky, unquoted 8+
	assert.equal(anonymizeText('password = "abc"'), 'password = "abc"');
});

// --- lokalni AI vrstva -----------------------------------------------------

/** Docasne nahradi globalni fetch mockem a po teste obnovi. */
async function withMockFetch(
	impl: typeof fetch,
	run: () => Promise<void>,
): Promise<void> {
	const orig = globalThis.fetch;
	globalThis.fetch = impl;
	try {
		await run();
	} finally {
		globalThis.fetch = orig;
	}
}

const jsonResponse = (body: unknown) =>
	new Response(JSON.stringify(body), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});

beforeEach(() => {
	// deterministicky stav nezavisly na env promennych stroje
	features.localai = false;
	settings.aiModel = "";
	settings.aiUrl = "http://localhost:11434/v1";
});

test("local-ai: vrati sanitizovany text z uspesne odpovedi", async () => {
	features.localai = true;
	settings.aiModel = "test-model";
	await withMockFetch(async () => jsonResponse({ choices: [{ message: { content: "clean text" } }] }), async () => {
		assert.equal(await anonymizeWithLocalAI("secret text"), "clean text");
	});
});

test("local-ai: posila spravny endpoint, model a system prompt", async () => {
	features.localai = true;
	settings.aiModel = "ornith-9b";
	let capturedUrl = "";
	let capturedBody = "";
	await withMockFetch(async (input, init) => {
		capturedUrl = String(input);
		capturedBody = String(init?.body ?? "");
		return jsonResponse({ choices: [{ message: { content: "x" } }] });
	}, async () => {
		await anonymizeWithLocalAI("user content here");
		assert.equal(capturedUrl, "http://localhost:11434/v1/chat/completions");
		const body = JSON.parse(capturedBody) as {
			model: string;
			messages: Array<{ role: string }>;
		};
		assert.equal(body.model, "ornith-9b");
		assert.deepEqual(
			body.messages.map((m) => m.role),
			["system", "user"],
		);
	});
});

test("local-ai: vrati null pri HTTP chybe serveru", async () => {
	features.localai = true;
	settings.aiModel = "test-model";
	await withMockFetch(async () => new Response("boom", { status: 500 }), async () => {
		assert.equal(await anonymizeWithLocalAI("text"), null);
	});
});

test("local-ai: vrati null kdyz server nereaguje", async () => {
	features.localai = true;
	settings.aiModel = "test-model";
	await withMockFetch(async () => {
		throw new Error("ECONNREFUSED");
	}, async () => {
		assert.equal(await anonymizeWithLocalAI("text"), null);
	});
});

test("local-ai: vrati null pri neocekavanem formatu odpovedi", async () => {
	features.localai = true;
	settings.aiModel = "test-model";
	await withMockFetch(async () => jsonResponse({ weird: true }), async () => {
		assert.equal(await anonymizeWithLocalAI("text"), null);
	});
});

test("local-ai: bez nastaveneho modelu volani neprobehne", async () => {
	features.localai = true;
	let called = false;
	await withMockFetch(async () => {
		called = true;
		return jsonResponse({ choices: [] });
	}, async () => {
		assert.equal(await anonymizeWithLocalAI("text"), null);
	});
	assert.equal(called, false);
});

test("local-ai: pri vypnutem prepinaci se nevola ani s nastavenym modelem", async () => {
	settings.aiModel = "test-model";
	features.localai = false;
	let called = false;
	await withMockFetch(async () => {
		called = true;
		return jsonResponse({ choices: [] });
	}, async () => {
		assert.equal(await anonymizeWithLocalAI("text"), null);
	});
	assert.equal(called, false);
});
