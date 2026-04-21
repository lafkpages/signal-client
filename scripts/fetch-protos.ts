#!/usr/bin/env bun

/**
 * Downloads the Signal protobuf schemas this project depends on and
 * generates TypeScript declarations for them via pbjs + pbts.
 *
 * Protos are not checked in — run `bun run scripts/fetch-protos.ts` (or
 * `bun run fetch-protos`) after cloning. Each source pins a commit SHA for
 * reproducible builds; bump the SHAs manually when you want to track
 * upstream changes.
 */
"";

import { mkdir, rename } from "node:fs/promises";
import { join } from "node:path";

import { $, CryptoHasher, file } from "bun";

// See https://u.luisafk.dev/kFAde
$.throws(true).env({
  ...process.env,
  FORCE_COLOR: Bun.enableANSIColors ? "1" : undefined,
});

const repo = "signalapp/Signal-Desktop";
const SOURCES = [
  {
    name: "SignalService.proto",
    ref: "c4ee32e9ee320de2379c4f4e9493d5a976cde248",
    hash: "7c664de3eb291b9e71e39da3b63d9def9243b054837179563dd2fb5d269518b0",
  },
  {
    name: "DeviceName.proto",
    ref: "3705b959d6dd0e49b88f3a143d08b3e3353ea6ae",
    hash: "fed7cd39825bb43f1727d6a7f8c8f155d410696441b0c288ea30eeca141b75b4",
  },
  {
    name: "DeviceMessages.proto",
    ref: "82517204444d3295bccfe2c33f5a3c9a510a856e",
    hash: "84472896446f3198dab4073d92f150b351be28563059eab1c49948e93c2374e3",
  },
];

const outDir = new URL("../protos", import.meta.url).pathname;
await mkdir(outDir, { recursive: true });

for (const src of SOURCES) {
  const url = `https://raw.githubusercontent.com/${repo}/${src.ref}/protos/${src.name}`;

  process.stdout.write(
    `Fetching ${src.name} from ${repo}@${src.ref.slice(0, 7)}... `,
  );

  const res = await fetch(url);
  if (!res.ok) {
    console.error(`FAILED: ${res.status} ${res.statusText} (${url})`);
    process.exit(1);
  }

  if (!res.body) {
    console.error(`FAILED: No response body (${url})`);
    process.exit(1);
  }

  const tmpOutPath = join(outDir, `_${src.name}`);
  const tmpOutFile = file(tmpOutPath);

  const hasher = new CryptoHasher("sha256");
  const writer = tmpOutFile.writer();

  writer.start();

  let totalBytes = 0;

  for await (const chunk of res.body) {
    if (!(chunk instanceof Uint8Array)) {
      throw new Error(`FAILED: Expected Uint8Array chunks (${url})`);
    }

    hasher.update(chunk);
    await writer.write(chunk);
    totalBytes += chunk.length;
  }

  await writer.end();
  const hash = hasher.digest("hex");

  if (hash !== src.hash) {
    console.error(
      `FAILED: Hash mismatch for ${src.name} (expected ${src.hash.slice(0, 7)}..., got ${hash})`,
    );
    process.exit(1);
  }

  await rename(tmpOutPath, join(outDir, src.name));

  console.log(`\t${totalBytes} bytes`);
}

console.log(`\nWrote ${SOURCES.length} protos to ${outDir}`);

// ---- Generate TS declarations via pbjs + pbts ----
//
// `src/protos.ts` imports both `generated.js` (runtime message classes and
// enums) and `generated.d.ts` (types) directly — no runtime `.proto` parsing.

const protoFiles = SOURCES.map((s) => join(outDir, s.name));
const generatedJs = join(outDir, "generated.js");
const generatedDts = join(outDir, "generated.d.ts");

await $`bun run -b pbjs --target static-module --wrap es6 --keep-case --out ${generatedJs} ${protoFiles}`;
await $`bun run pbts --out ${generatedDts} ${generatedJs}`;

console.log(`\nGenerated ${generatedDts}`);
