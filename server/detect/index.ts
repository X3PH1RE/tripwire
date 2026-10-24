import { Engine } from "./engine";
import gitleaks from "./rules/gitleaks.json";
import { tripwirePack } from "./rules/tripwire";
import type { Pack } from "./schema";

export { Engine } from "./engine";
export type { Hit } from "./engine";
export type { Confidence, Pack, RuleDef } from "./schema";

let shared: Engine | undefined;

/** The engine every scan uses: Tripwire's own rules first, so they win on identical values, then the imported Gitleaks baseline. */
export function defaultEngine(): Engine {
  return (shared ??= new Engine([tripwirePack, gitleaks as Pack]));
}
