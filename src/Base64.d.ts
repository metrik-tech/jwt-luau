interface Base64 {
	encode: (input: string) => string;
	decode: (input: string) => string;
}

declare const Base64: Base64;

export = Base64;
