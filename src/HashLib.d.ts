interface HashLib {
	md5: (message: string) => string;
	sha1: (message: string) => string;

	sha224: (message: string) => string;
	sha256: (message: string) => string;
	sha512_224: (message: string) => string;
	sha512_256: (message: string) => string;
	sha384: (message: string) => string;
	sha512: (message: string) => string;
	sha3_224: (message: string) => string;
	sha3_256: (message: string) => string;
	sha3_384: (message: string) => string;
	sha3_512: (message: string) => string;
	shake128: (message: string, digest_size_in_bytes: number) => string;
	shake256: (message: string, digest_size_in_bytes: number) => string;

	hmac: (hash_func: (message: string) => string, key: string, message: string, AsBinary: boolean) => string;

	hex_to_bin: (hex: string) => string;
	base64_to_bin: (base64: string) => string;
	bin_to_base64: (bin: string) => string;

	base64_encode: (message: string) => string;
	base64_decode: (message: string) => string;
}

declare const HashLib: HashLib;

export = HashLib;
