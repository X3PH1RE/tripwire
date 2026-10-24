/**
 * Aho-Corasick over ASCII keywords: one pass over a file finds every keyword and the line it is on,
 * instead of one `indexOf` sweep per keyword. Input must already be lower-cased.
 */
export class KeywordIndex {
  private readonly next: Int32Array; // dense DFA: next[state << 7 | ascii]
  private readonly outs: (number[] | undefined)[];
  readonly size: number;

  constructor(keywords: string[]) {
    this.size = keywords.length;
    let states = 1;
    for (const k of keywords) states += k.length;
    const goto = new Int32Array(states << 7).fill(-1);
    const outs: (number[] | undefined)[] = new Array(states);
    let count = 1;
    keywords.forEach((k, id) => {
      let s = 0;
      for (let i = 0; i < k.length; i++) {
        const c = k.charCodeAt(i);
        if (c >= 128) throw new Error(`keyword must be ASCII: ${k}`);
        const at = (s << 7) | c;
        if (goto[at] === -1) goto[at] = count++;
        s = goto[at];
      }
      (outs[s] ??= []).push(id);
    });

    // BFS: fail links, merged outputs, and a complete transition table so scanning never backtracks.
    const fail = new Int32Array(count);
    const queue: number[] = [];
    for (let c = 0; c < 128; c++) {
      const s = goto[c];
      if (s === -1) goto[c] = 0;
      else queue.push(s);
    }
    for (let head = 0; head < queue.length; head++) {
      const s = queue[head];
      for (let c = 0; c < 128; c++) {
        const t = goto[(s << 7) | c];
        const viaFail = goto[(fail[s] << 7) | c];
        if (t === -1) goto[(s << 7) | c] = viaFail;
        else {
          fail[t] = viaFail;
          const inherited = outs[viaFail];
          if (inherited) outs[t] = [...(outs[t] ?? []), ...inherited];
          queue.push(t);
        }
      }
    }
    this.next = goto.slice(0, count << 7);
    this.outs = outs.slice(0, count);
  }

  /** Calls `found(keywordId, lineIndex)` once per keyword per line. `text` must be lower-cased; lines are counted by `\n`. */
  scan(text: string, found: (keyword: number, line: number) => void): void {
    const lastLine = new Int32Array(this.size).fill(-1);
    const { next, outs } = this;
    let state = 0;
    let line = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c === 10) line++;
      state = next[(state << 7) | (c < 128 ? c : 0)];
      const o = outs[state];
      if (o !== undefined)
        for (let j = 0; j < o.length; j++) {
          const k = o[j];
          if (lastLine[k] !== line) {
            lastLine[k] = line;
            found(k, line);
          }
        }
    }
  }
}
