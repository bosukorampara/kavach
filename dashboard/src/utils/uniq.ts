export function uniqStrings(arr: string[]): string[] {
  const seen: Record<string, true> = {};
  const out: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const v = String(arr[i]);
    if (!seen[v]) { seen[v] = true; out.push(v); }
  }
  return out;
}

