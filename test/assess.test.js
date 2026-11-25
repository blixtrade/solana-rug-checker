import test from "node:test";
import assert from "node:assert/strict";
import { assess } from "../lib/assess.js";

const holders = (pcts, extra = {}) => pcts.map((pct, i) => ({ owner: "W" + i, address: "A" + i, pct, insider: false, ...extra }));
const safe = () => ({
  mint: "SafeMint11111111111111111111111111111111111",
  mintInfo: { mintAuthority: null, freezeAuthority: null, supply: "1000000", decimals: 6, program: "spl-token" },
  report: { topHolders: holders([2, 2, 1, 1, 1]), knownAccounts: {}, creator: "C", creatorBalance: 0, risks: [], token: {} },
  pair: { dexId: "raydium", liquidity: { usd: 250000 }, pairCreatedAt: Date.now() - 86400_000 * 30, txns: { h24: { buys: 100, sells: 90 } } },
});
const titles = (r) => r.findings.map((f) => f.title).join(" | ");

test("a clean token scores low", () => {
  const r = assess(safe());
  assert.equal(r.score, 0);
  assert.equal(r.verdict, "LOW RISK");
});

test("active mint and freeze authority is high risk", () => {
  const d = safe();
  d.mintInfo.mintAuthority = "Auth";
  d.mintInfo.freezeAuthority = "Auth";
  const r = assess(d);
  assert.equal(r.score, 70);
  assert.equal(r.verdict, "HIGH RISK");
  assert.equal(r.findings[0].level, "danger");
});

test("pools are excluded from holder concentration", () => {
  const d = safe();
  d.report.topHolders = [{ owner: "POOL", address: "PA", pct: 80 }, ...holders([2, 2])];
  d.report.knownAccounts = { POOL: { name: "Raydium Pool", type: "AMM" } };
  assert.equal(assess(d).score, 0);
});

test("concentrated supply and thin liquidity add up", () => {
  const d = safe();
  d.report.topHolders = holders([20, 15, 10, 8]);
  d.pair.liquidity.usd = 3000;
  const r = assess(d);
  assert.equal(r.score, 25 + 15 + 20);
  assert.match(titles(r), /Top 10 wallets hold 53\.0%/);
});

test("token-2022 transfer tax and permanent delegate are caught", () => {
  const d = safe();
  d.mintInfo.extensions = [
    { extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 1000 } } },
    { extension: "permanentDelegate", state: { delegate: "Someone" } },
    { extension: "permanentDelegate", state: { delegate: null } },
  ];
  const r = assess(d);
  assert.match(titles(r), /Transfer tax 10\.00%/);
  assert.match(titles(r), /Permanent delegate/);
  assert.equal(r.score, 70);
});

test("buys with zero sells is flagged as a honeypot pattern", () => {
  const d = safe();
  d.pair.txns.h24 = { buys: 400, sells: 0 };
  assert.match(titles(assess(d)), /Nobody has sold/);
});

test("a pump.fun mint with no pool is a warning, not a failure", () => {
  const d = safe();
  d.mint = "AF4R5UZVcnghCSko7Y2P1UNKNVxQCL6q1Jvs5fnppump";
  d.pair = null;
  const r = assess(d);
  assert.equal(r.score, 8);
});

test("rugged flag maxes the score, and extra RugCheck risks are included once", () => {
  const d = safe();
  d.report.rugged = true;
  d.report.risks = [{ name: "Mutable metadata", level: "warn", description: "x" }, { name: "Low Liquidity", level: "danger" }];
  const r = assess(d);
  assert.equal(r.score, 100);
  assert.match(titles(r), /Mutable metadata/);
  assert.doesNotMatch(titles(r), /Low Liquidity/);
});

test("works from the RugCheck report alone when the RPC is down", () => {
  const d = safe();
  d.mintInfo = null;
  d.report.token = { mintAuthority: "Auth", freezeAuthority: null, supply: 1000 };
  assert.equal(assess(d).score, 35);
});

test("a coin on the pump.fun bonding curve is not treated as zero liquidity", () => {
  const d = safe();
  d.pair = { dexId: "pumpfun", pairCreatedAt: Date.now() - 120_000, txns: { h24: { buys: 3, sells: 1 } } };
  const r = assess(d);
  assert.equal(r.score, 13);
  assert.match(titles(r), /bonding curve/);
});

test("RugCheck's creator rug history is reported, and its holder concentration risk is not counted twice", () => {
  const d = safe();
  d.report.risks = [
    { name: "Creator history of rugged tokens", value: "", description: "Creator has a history of rugging tokens.", level: "danger" },
    { name: "High holder concentration", value: "", description: "The top 10 users hold more than 50% token supply", level: "warn" },
  ];
  const r = assess(d);
  assert.match(titles(r), /Creator history of rugged tokens/);
  assert.doesNotMatch(titles(r), /High holder concentration/);
  assert.equal(r.score, 15);
});

test("creator share comes from the holder list when RugCheck's creatorBalance is 0", () => {
  const d = safe(); // supply 1,000,000 raw units
  d.report.creatorBalance = 0;
  d.report.topHolders = [...holders([2, 2]), { owner: "C", address: "CA", amount: 32500, pct: 3.25, insider: false }];
  assert.match(titles(assess(d)), /Creator holds 3\.25%/);

  d.report.topHolders[2].amount = 80000;
  d.report.topHolders[2].pct = 8;
  const r = assess(d);
  assert.match(titles(r), /Creator holds 8\.0%/);
  assert.ok(r.findings.some((f) => f.title.startsWith("Creator holds") && f.level === "warn" && f.points === 8));

  d.report.topHolders = holders([2, 2]);
  assert.match(titles(assess(d)), /Creator is not a top holder/);
  assert.doesNotMatch(titles(assess(d)), /Creator holds 0%/);
});

// Issue #7: one small test per untested assess() branch, each from safe().
const NOW = 1_800_000_000_000; // fixed "now" so the age tests are deterministic

test("transfer hook and non-transferable extensions are flagged", () => {
  const d = safe();
  d.mintInfo.extensions = [
    { extension: "transferHook", state: {} },
    { extension: "nonTransferable", state: {} },
  ];
  const r = assess(d);
  assert.equal(r.score, 50);
  assert.ok(r.findings.some((f) => f.title === "Transfer hook" && f.level === "warn" && f.points === 10));
  assert.ok(r.findings.some((f) => f.title === "Non-transferable" && f.level === "danger" && f.points === 40));
});

test("default account state counts only when frozen", () => {
  const d = safe();
  d.mintInfo.extensions = [{ extension: "defaultAccountState", state: { accountState: "frozen" } }];
  const r = assess(d);
  assert.equal(r.score, 15);
  assert.match(titles(r), /Default account state/);

  const e = safe();
  e.mintInfo.extensions = [{ extension: "defaultAccountState", state: { accountState: "initialized" } }];
  assert.equal(assess(e).score, 0);
  assert.doesNotMatch(titles(assess(e)), /Default account state/);
});

test("transfer tax under 5% is a warning, not a danger", () => {
  const d = safe();
  d.mintInfo.extensions = [{ extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 200 } } }];
  const r = assess(d);
  assert.equal(r.score, 10);
  assert.ok(r.findings.some((f) => f.title === "Transfer tax 2.00%" && f.level === "warn" && f.points === 10));
});

test("insider points are capped at 15", () => {
  const d = safe();
  d.report.topHolders = holders([2, 2, 1, 1, 1, 1]).map((h) => ({ ...h, insider: true }));
  const r = assess(d);
  // 6 insiders would be 18 points uncapped; the cap holds it at 15.
  assert.ok(r.findings.some((f) => f.title === "6 top holders flagged as insiders" && f.level === "warn" && f.points === 15));
  assert.equal(r.score, 15);
});

test("creator share above 5% warns, between 0 and 5% is ok", () => {
  const d = safe();
  d.report.creatorBalance = 80000; // 8% of the 1,000,000 supply
  const r = assess(d);
  assert.equal(r.score, 8);
  assert.ok(r.findings.some((f) => f.title === "Creator holds 8.0%" && f.level === "warn" && f.points === 8));

  const e = safe();
  e.report.creatorBalance = 30000; // 3%
  const s = assess(e);
  assert.equal(s.score, 0);
  assert.ok(s.findings.some((f) => f.title === "Creator holds 3.00%" && f.level === "ok" && f.points === 0));
});

test("a pump.fun curve coin under an hour old adds 5", () => {
  const d = safe();
  d.pair = { dexId: "pumpfun", pairCreatedAt: NOW - 1800_000, txns: { h24: { buys: 3, sells: 1 } } };
  const r = assess({ ...d, now: NOW });
  assert.equal(r.score, 13); // 8 for the bonding curve, 5 for being under an hour old
  assert.match(titles(r), /Launched under an hour ago/);
});

test("a pool under an hour old adds 5", () => {
  const d = safe();
  d.pair.pairCreatedAt = NOW - 1800_000;
  const r = assess({ ...d, now: NOW });
  assert.equal(r.score, 5);
  assert.match(titles(r), /Pool is under an hour old/);
});

test("a RugCheck insider network is flagged", () => {
  const d = safe();
  d.report.graphInsidersDetected = 4;
  const r = assess(d);
  assert.equal(r.score, 5);
  assert.match(titles(r), /Insider network of 4 wallets/);
});

test("findings are sorted danger, then warn, then ok, by points within each level", () => {
  const d = safe();
  d.mintInfo.extensions = [
    { extension: "transferHook", state: {} },
    { extension: "defaultAccountState", state: { accountState: "frozen" } },
    { extension: "nonTransferable", state: {} },
    { extension: "transferFeeConfig", state: { newerTransferFee: { transferFeeBasisPoints: 1000 } } },
  ];
  const r = assess(d);
  assert.equal(r.score, 95);
  const ranked = r.findings.filter((f) => f.points > 0).map((f) => `${f.level}:${f.points}:${f.title}`);
  assert.deepEqual(ranked, [
    "danger:40:Non-transferable",
    "danger:30:Transfer tax 10.00%",
    "warn:15:Default account state",
    "warn:10:Transfer hook",
  ]);
  assert.equal(r.findings[0].level, "danger");
  assert.equal(r.findings.at(-1).level, "ok");
});
