import { encode, decode } from "./Base64";
import hash from "./HashLib";
import { HttpService } from "@rbxts/services";

const algsSign = {
	HS256: (message: string, key: string) => hash.hmac(hash.sha256, key, message, true),
	HS384: (message: string, key: string) => hash.hmac(hash.sha384, key, message, true),
	HS512: (message: string, key: string) => hash.hmac(hash.sha512, key, message, true),
} as {
	[key: string]: (message: string, key: string) => string;
};

const algsVerify = {
	HS256: (message: string, key: string, signature: string) =>
		hash.hmac(hash.sha256, key, message, true) === signature,
	HS384: (message: string, key: string, signature: string) =>
		hash.hmac(hash.sha384, key, message, true) === signature,
	HS512: (message: string, key: string, signature: string) =>
		hash.hmac(hash.sha512, key, message, true) === signature,
} as {
	[key: string]: (message: string, key: string, signature: string) => boolean;
};

function base64urlEncode(str: string) {
	return encode(str).gsub("+", "-")[0].gsub("/", "_")[0].gsub("=", "");
}

function base64urlDecode(str: string) {
	const remainder = str.size() % 4;

	if (remainder > 0) {
		str = str + string.rep("=", 4 - remainder);
	}

	return decode(str.gsub("-", "+")[0].gsub("_", "/")[0].gsub("=", "")[0]);
}

function tokenize(str: string, div: string, len: number): string[] {
	const result: string[] = [];
	let pos = 0;

	while (len > 1) {
		const st = str.find(div, pos, true);
		if (!st[0]) break;
		const sp = st[0] + div.size() - 1;

		result.push(str.sub(pos, st[0] - 1));
		pos = sp + 1;

		len = len - 1;
	}

	result.push(str.sub(pos));

	return result;
}

function encodeJWT(data: unknown, key: string, alg: string | undefined = "HS256"): string {
	if (typeOf(data) !== "table" || !table) {
		error("data must be a table");
	}

	if (typeOf(key) !== "string" || !key) {
		error("key must be a string");
	}

	if (typeOf(alg) !== "string" || !alg) {
		error("alg must be a string");
	}

	if (!algsSign[alg]) {
		error("alg must be a valid algorithm");
	}

	const header = { typ: "JWT", alg: alg };
	const segments = [base64urlEncode(HttpService.JSONEncode(header)), base64urlEncode(HttpService.JSONEncode(data))];
	const signingInput = segments.join(".");
	const signature = base64urlEncode(algsSign[alg](signingInput, key));

	segments.push(signature);

	return segments.join(".");
}

function decodeJWT(
	data: string,
	key: string | undefined,
	verify: boolean | undefined,
): {
	header: { alg: string; typ: string };
	body: { exp: number; iat: number; nbf: number; [key: string]: unknown };
	signature: string;
} {
	if (!key) {
		verify = false;
	} else if (key && verify === undefined) {
		verify = true;
	}

	if (typeOf(data) !== "string" || !data) {
		error("data must be a string");
	}

	if (typeOf(key) !== "string" || !key) {
		error("key must be a string");
	}

	if (typeOf(verify) !== "boolean") {
		error("verify must be a boolean");
	}

	const segments = tokenize(data, ".", 3);

	if (segments.size() !== 3) {
		error("not enough or too many segments");
	}

	const headerSegment = segments[0];
	const payloadSegment = segments[1];
	const signatureSegment = segments[2];

	const [success, payload] = pcall(() => {
		return {
			header: HttpService.JSONDecode(base64urlDecode(headerSegment)) as { alg: string; typ: string },
			body: HttpService.JSONDecode(base64urlDecode(payloadSegment)) as {
				exp: number;
				iat: number;
				nbf: number;
				[key: string]: unknown;
			},
			signature: base64urlDecode(signatureSegment),
		};
	});

	if (!success) {
		error("failed to decode JWT");
	}

	if (verify) {
		verifyJWT(data, key, true);
	}

	return payload;
}

function verifyJWT(data: string, key: string, throwErrors: boolean | undefined = false): boolean {
	if (typeOf(data) !== "string" || !data) {
		error("data must be a string");
	}

	if (typeOf(key) !== "string" || !key) {
		error("key must be a string");
	}

	const segments = tokenize(data, ".", 3);

	if (segments.size() !== 3) {
		if (throwErrors) error("not enough or too many segments");

		return false;
	}

	const headerSegment = segments[0];
	const payloadSegment = segments[1];
	const signatureSegment = segments[2];

	const header = HttpService.JSONDecode(base64urlDecode(headerSegment)) as { alg: string; typ: string };
	const body = HttpService.JSONDecode(base64urlDecode(payloadSegment)) as { exp: number; iat: number; nbf: number };

	if (!header.typ || header.typ !== "JWT") {
		if (throwErrors) error("typ must be JWT");

		return false;
	}

	if (!header.alg || typeOf(header.alg) !== "string") {
		if (throwErrors) error("alg must be a string");

		return false;
	}

	if (!algsVerify[header.alg]) {
		if (throwErrors) error("alg must be a valid algorithm");

		return false;
	}

	if (body.exp && typeOf(body.exp) !== "number") {
		if (throwErrors) error("exp must be a number");

		return false;
	}

	if (body.iat && typeOf(body.iat) !== "number") {
		if (throwErrors) error("iat must be a number");

		return false;
	}

	if (body.nbf && typeOf(body.nbf) !== "number") {
		if (throwErrors) error("nbf must be a number");

		return false;
	}

	if (body.exp && body.exp < os.time()) {
		if (throwErrors) error("exp has expired");

		return false;
	}

	if (body.iat && body.iat > os.time()) {
		if (throwErrors) error("iat is in the future");

		return false;
	}

	if (body.nbf && body.nbf > os.time()) {
		if (throwErrors) error("nbf is in the future");

		return false;
	}

	if (!algsVerify[header.alg](headerSegment + "." + payloadSegment, key, signatureSegment)) {
		if (throwErrors) error("signature is invalid");

		return false;
	}

	return true;
}

export = {
	sign: encodeJWT,
	decode: decodeJWT,
	verify: verifyJWT,
};
