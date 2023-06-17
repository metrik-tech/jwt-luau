# `jwt-luau`

LuaU/`roblox-ts` fork of [x25/luajwt](https://github.com/x25/luajwt) that works with Roblox. Currently only supports symmetric HS(256/384/512).

Wrote this to verify Metrik tokens in our SDK. This is not a full implementation of the JWT spec, but it should be enough for most use cases.

## Installation

### via `roblox-ts`
```bash
npm install @rbxts/jwt
```
### via Wally
```bash
jwt = "metrik-tech/jwt@0.1.0"
```
### via `rbxm`/`rbxmx`
Download from Releases page. Latest release can be found [here](
    https://github.com/metrik-tech/jwt-luau/releases/latest
)

## Usage

### TypeScript
```ts
import { decode, verify, sign } from "@rbxts/jwt";

// sign jwt
const jwt = sign({ foo: "bar", exp: 1893481200 }, "secret");

// sign jwt with algorithm
const hs483jwt = sign({ foo: "bar", exp: 1893481200 }, "secret", "HS384");

// verify jwt
const isValid = verify(jwt, "secret");

// verify jwt and throw
const throwIfInvalid = verify(jwt, "secret", true);

// decode jwt
const decoded = decode(jwt);

// decode jwt with verification (throws)
const validDecoded = decode(jwt, "secret", true)
```

### Lua
```lua
local Jwt = require(path.to.jwt)

-- sign jwt
local jwt = Jwt.sign({ foo = "bar", exp = 1893481200 }, "secret")

-- sign jwt with algorithm
local hs384jwt = Jwt.sign({ foo = "bar", exp = 1893481200 }, "secret", "HS384")

-- verify jwt
local isValid = Jwt.verify(jwt, "secret")

-- verify jwt and throw
local throwIfInvalid = Jwt.verify(jwt, "secret", true)

-- decode jwt
local decoded = Jwt.decode(jwt)

-- decode jwt with verification (throws)
local validDecoded = decode(jwt, "secret", true)
```




