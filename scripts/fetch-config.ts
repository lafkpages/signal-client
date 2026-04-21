#!/usr/bin/env bun

async function downloadConfigFile(name: string) {
  const currentConfigFile = Bun.file(`./src/config/${name}.json`);
  let currentConfig: string | null = null;

  try {
    currentConfig = await currentConfigFile.text();
  } catch (e) {
    if (!e || typeof e !== "object" || !("code" in e) || e.code !== "ENOENT") {
      console.error("Failed to read existing", name, "config:", e);
    }
  }

  const res = await fetch(
    `https://raw.githubusercontent.com/signalapp/Signal-Desktop/refs/heads/main/config/${name}.json`,
  );

  if (!res.ok) {
    console.error(
      "Failed to fetch Signal Desktop's",
      name,
      "config:",
      res.status,
      res.statusText,
    );
    process.exit(1);
  }

  const resContentType = res.headers.get("content-type");

  if (
    !resContentType?.startsWith("application/json") &&
    !resContentType?.startsWith("text/plain")
  ) {
    console.error(
      `Received unexpected content type for config ${name}:`,
      resContentType,
    );
    process.exit(1);
  }

  const newConfig = await res.text();

  try {
    JSON.parse(newConfig);
  } catch {
    console.error("Fetched config", name, "is not valid JSON");
    process.exit(1);
  }

  if (newConfig === currentConfig) {
    console.log("Config", name, "is up to date, no changes needed.");
    return;
  }

  await currentConfigFile.write(newConfig);
  console.log("Config", name, "updated successfully.");
}

await downloadConfigFile("default");
await downloadConfigFile("production");
