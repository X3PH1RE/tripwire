import { readFileSync } from "node:fs";
import { main } from "./main";

const input = (name: string, fallback = "") => (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim() || fallback;

function baseSha(): string | undefined {
  try {
    return JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH ?? "", "utf8")).pull_request?.base?.sha;
  } catch {
    return undefined;
  }
}

const token = input("token");
if (token) process.env.GITHUB_TOKEN = token;
const argv = ["scan", input("path", "."), "--github", "--history", input("history", "300"), "--fail-on-vulns", input("fail-on-vulns", "none")];
const base = baseSha();
if (base) argv.push("--diff", base);
if (base && input("comment", "true") === "true") argv.push("--comment");
if (input("fail-on-secrets", "true") === "false") argv.push("--no-fail-secrets");
if (input("verify", "false") === "true") argv.push("--verify");
if (input("baseline", "true") === "false") argv.push("--no-baseline");
argv.push("--min-confidence", input("min-confidence", "low"));

main(argv).then(
  (code) => process.exit(code),
  (e: Error) => {
    process.stdout.write(`::error title=Tripwire::${e.message}\n`);
    process.exit(2);
  },
);
