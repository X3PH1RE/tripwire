import { main } from "./main";

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: Error) => {
    process.stderr.write(`tripwire: ${e.message}\n`);
    process.exit(2);
  },
);
