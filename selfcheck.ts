// Minimalni self-check anonymizacnich regexu.
// Spusteni: node --experimental-strip-types selfcheck.ts

import { anonymizeText } from "./index.ts";

const cases: Array<[string, boolean]> = [
	['password = "SuperTajneHeslo123"', true],
	["API_KEY='sk-12345678'", true],
	["token: eyJhbGciOiJIUzI1NiJ9.xxx", true],
	["hex 0123456789abcdef0123456789abcdef", true],
	// leaky z prvniho testu — podtrzitkove prefixy
	['database_password = "SuperTajneHeslo123"', true],
	["auth_token: 'eyJhbGciOiJIUzI1NiJ9.test.sig'", true],
	["username = jan.novak", false], // zamerne jeste nechytame (jen demo sada)
];

let failed = 0;
for (const [input, shouldRedact] of cases) {
	const out = anonymizeText(input);
	const ok = out.includes("[REDACTED]") === shouldRedact;
	if (ok) {
		console.log(`ok:   ${out}`);
	} else {
		failed++;
		console.log(`FAIL: ${input}\n  -> ${out}`);
	}
}

if (failed > 0) {
	console.error(`${failed} case(s) failed`);
	process.exit(1);
}
console.log("\nAll checks passed.");
