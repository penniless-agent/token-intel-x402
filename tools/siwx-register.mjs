import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

// Cross-platform offline wallet home. The key never lives in a repo.
const HOME = process.env.USERPROFILE || process.env.HOME || "";
const WALLET_DIR = join(HOME, ".config", "agent-wallet");
const require = createRequire(join(WALLET_DIR, "package.json"));
const { Wallet, getAddress } = require("ethers");

const ENDPOINT = "https://www.x402scan.com/api/x402/registry/register-origin";
const ORIGIN = process.env.SERVICE_ORIGIN || "https://token-intel-x402.meisburply.deno.net";

const w = JSON.parse(readFileSync(join(WALLET_DIR, "wallet.json"), "utf8"));
const wallet = new Wallet(w.privateKey);
const address = getAddress(wallet.address); // EIP-55 checksum

const body = JSON.stringify({ origin: ORIGIN });
const post = (headers = {}) =>
  fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });

// 1. fetch fresh challenge
const c = await post();
if (c.status !== 402) throw new Error(`expected 402 challenge, got ${c.status}: ${await c.text()}`);
const info = (await c.json()).extensions["sign-in-with-x"].info;

// 2. build EIP-4361 message (numeric chain id inside the message)
const chainNum = info.chainId.split(":").pop();
const lines = [
  `${info.domain} wants you to sign in with your Ethereum account:`,
  address,
  "",
  info.statement,
  "",
  `URI: ${info.uri}`,
  `Version: ${info.version}`,
  `Chain ID: ${chainNum}`,
  `Nonce: ${info.nonce}`,
  `Issued At: ${info.issuedAt}`,
];
if (info.expirationTime) lines.push(`Expiration Time: ${info.expirationTime}`);
if (info.resources?.length) lines.push("Resources:", ...info.resources.map((r) => `- ${r}`));
const message = lines.join("\n");

// 3. sign (EIP-191 personal_sign)
const signature = await wallet.signMessage(message);

// 4. decomposed payload -> base64 header
const payload = {
  domain: info.domain,
  address,
  statement: info.statement,
  uri: info.uri,
  version: info.version,
  chainId: info.chainId, // CAIP-2 in payload
  type: "eip191",
  nonce: info.nonce,
  issuedAt: info.issuedAt,
  expirationTime: info.expirationTime,
  ...(info.resources?.length ? { resources: info.resources } : {}),
  signature,
};
const header = Buffer.from(JSON.stringify(payload)).toString("base64");

// 5. authenticated call
const r = await post({ "sign-in-with-x": header });
console.log("HTTP", r.status);
console.log(await r.text());
