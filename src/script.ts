import { exportKeys } from ".";
import fs from "fs";

async function main() {
  try {
    const mnemonic = fs.readFileSync("recovery_phrase.txt", "utf8").trim();
    const backupStr = fs.readFileSync("backup.json", "utf8");
    const backup = JSON.parse(backupStr);

    const exportedKeys = await exportKeys(mnemonic, backup);
    fs.writeFileSync(
      "exported-keys.json",
      JSON.stringify(exportedKeys, null, 2)
    );
    console.log("Saved exported keys to exported-keys.json!");
  } catch (e) {
    if (e instanceof Error) {
      if (e.message.startsWith("ENOENT: no such file or directory")) {
        throw new Error(
          "File not found, please add a file named 'recovery_phrase.txt' with your secret phrase and a file named 'backup.json' with your backup data, in the current working directory."
        );
      }
    }

    console.log(e);
  }
}

main();
