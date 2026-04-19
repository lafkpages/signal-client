#!/usr/bin/env bun
// Downloads the Signal protobuf schemas this project depends on and
// generates TypeScript declarations for them via pbjs + pbts.
//
// Protos are not checked in — run `bun run scripts/fetch-protos.ts` (or
// `bun run fetch-protos`) after cloning. Each source pins a commit SHA for
// reproducible builds; bump the SHAs manually when you want to track
// upstream changes.

import { $ } from "bun";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// See https://u.luisafk.dev/kFAde
$.throws(true).env({
  ...process.env,
  FORCE_COLOR: Bun.enableANSIColors ? "1" : undefined,
});

type ProtoSource = {
  name: string;
  repo: string;
  ref: string;
  path: string;
};

// SignalService.proto lives in Signal-Android; the provisioning-flow protos
// (DeviceName, DeviceMessages) are maintained in Signal-Desktop.
const SOURCES: ProtoSource[] = [
  {
    name: "SignalService.proto",
    repo: "signalapp/Signal-Android",
    ref: "f04a0533cbce3bf64b609861cdb35cf59ebfe8a9",
    path: "lib/libsignal-service/src/main/protowire/SignalService.proto",
  },
  {
    name: "DeviceName.proto",
    repo: "signalapp/Signal-Desktop",
    ref: "3705b959d6dd0e49b88f3a143d08b3e3353ea6ae",
    path: "protos/DeviceName.proto",
  },
  {
    name: "DeviceMessages.proto",
    repo: "signalapp/Signal-Desktop",
    ref: "82517204444d3295bccfe2c33f5a3c9a510a856e",
    path: "protos/DeviceMessages.proto",
  },
];

const outDir = new URL("../protos", import.meta.url).pathname;
await mkdir(outDir, { recursive: true });

for (const src of SOURCES) {
  const url = `https://raw.githubusercontent.com/${src.repo}/${src.ref}/${src.path}`;

  process.stdout.write(
    `Fetching ${src.name} from ${src.repo}@${src.ref.slice(0, 7)}... `,
  );

  const res = await fetch(url);
  if (!res.ok) {
    console.error(`FAILED: ${res.status} ${res.statusText} (${url})`);
    process.exit(1);
  }

  await Bun.write(join(outDir, src.name), res);
  console.log(`${res.headers.get("content-length") ?? "unknown"} bytes`);
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
