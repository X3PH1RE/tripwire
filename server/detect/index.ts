import { Engine } from "./engine";
import { tripwirePack } from "./rules/tripwire";

export { Engine } from "./engine";
export type { Hit } from "./engine";
export type { Confidence, Pack, RuleDef } from "./schema";

let shared: Engine | undefined;

/** The engine every scan uses: Tripwire's own rules first, then the imported baseline. */
export function defaultEngine(): Engine {
  return (shared ??= new Engine([tripwirePack]));
}
