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
		base64urlEncode(hash.hmac(hash.sha256, key, message, true)) === signature,
	HS384: (message: string, key: string, signature: string) =>
		base64urlEncode(hash.hmac(hash.sha384, key, message, true)) === signature,
	HS512: (message: string, key: string, signature: string) =>
		base64urlEncode(hash.hmac(hash.sha512, key, message, true)) === signature,
} as {
	[key: string]: (message: string, key: string, signature: string) => boolean;
};

function base64urlEncode(str: string) {
	return encode(str).gsub("+", "-")[0].gsub("/", "_")[0].gsub("=", "")[0];
}

function encodeJWT(data: unknown, key: string, alg = "HS256"): string {
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

	const segments = [encode(HttpService.JSONEncode(header)), encode(HttpService.JSONEncode(data))];

	const signingInput = segments.join(".");
	const signature = base64urlEncode(algsSign[alg](signingInput, key));

	segments.push(signature);

	return segments.join(".");
}

function decodeJWT(
	data: string,
	key?: string,
	verify?: boolean,
): {
	header: { alg: string; typ: string };
	body: { exp: number; iat: number; nbf: number; [key: string]: unknown };
} {
	if (!key) {
		verify = false;
	} else if (key && verify === undefined) {
		verify = true;
	}

	if (typeOf(data) !== "string" || !data) {
		error("data must be a string");
	}

	if (typeOf(verify) !== "boolean") {
		error("verify must be a boolean");
	}

	const segments = data.split(".");

	if (segments.size() !== 3) {
		error("not enough or too many segments");
	}

	const headerSegment = segments[0];
	const payloadSegment = segments[1];

	const [success, payload] = pcall(() => {
		return {
			header: HttpService.JSONDecode(decode(headerSegment)) as { alg: string; typ: string },
			body: HttpService.JSONDecode(decode(payloadSegment)) as {
				exp: number;
				iat: number;
				nbf: number;
				[key: string]: unknown;
			},
		};
	});

	if (!success) {
		error("failed to decode JWT");
	}

	if (verify && key) {
		verifyJWT(data, key, true);
	}

	return payload;
}

function verifyJWT(data: string, key: string, throwErrors = false): boolean {
	if (typeOf(data) !== "string" || !data) {
		error("data must be a string");
	}

	if (typeOf(key) !== "string" || !key) {
		error("key must be a string");
	}

	const segments = data.split(".");

	if (segments.size() !== 3) {
		if (throwErrors) error("not enough or too many segments");

		return false;
	}

	const headerSegment = segments[0];
	const payloadSegment = segments[1];
	const signatureSegment = segments[2];

	const header = HttpService.JSONDecode(decode(headerSegment)) as { alg: string; typ: string };
	const body = HttpService.JSONDecode(decode(payloadSegment)) as { exp: number; iat: number; nbf: number };

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
