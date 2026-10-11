/**
 * Decides whether a column holds personal or secret data, from its name and
 * from the shape of sampled values. Values are only looked at in memory and
 * are never returned or printed.
 */

const BY_NAME: [RegExp, string][] = [
  [/e[-_]?mail/i, "email"],
  [/phone|mobile|msisdn|gsm|telefon/i, "phone"],
  [/ssn|tc_?kimlik|tckn|national_?id|passport|tax_?id|vkn/i, "national id"],
  [/password|passwd|pwd|(^|_)hash($|_)/i, "password"],
  [/token|secret|api[-_]?key|private[-_]?key|(^|_)otp|refresh_?token/i, "secret"],
  [/address|street|zip|postcode|adres/i, "address"],
  [/birth|(^|_)dob($|_)|(^|_)age$/i, "birth date"],
  [/(^|_)ip($|_)|ip_?addr/i, "ip"],
  [/(^|_)(lat|lng|lon|latitude|longitude|location|geo)($|_)/i, "location"],
  [/iban|card_?number|cvv|account_?number/i, "payment"],
];

const BY_VALUE: [RegExp, string][] = [
  [/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i, "email"],
  // International format only; bare digit strings are too often ids or dates.
  [/^(\+|00)[1-9][\d\s()-]{7,}\d$/, "phone"],
  [/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+$/, "secret"],
  [/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/, "payment"],
];

export function classifyColumn(name: string, samples: unknown[] = []): string | null {
  for (const [re, kind] of BY_NAME) if (re.test(name)) return kind;
  for (const v of samples) {
    if (typeof v !== "string") continue;
    for (const [re, kind] of BY_VALUE) if (re.test(v.trim())) return kind;
  }
  return null;
}

/** "email, phone" for the sensitive columns of some rows, or "" when none. */
export function sensitiveColumns(rows: Record<string, unknown>[], extraColumns: string[] = []): string {
  const columns = new Set([...extraColumns, ...rows.flatMap((r) => Object.keys(r))]);
  const hits: string[] = [];
  for (const col of columns) {
    const kind = classifyColumn(col, rows.map((r) => r[col]));
    if (kind) hits.push(kind === col ? col : `${col} (${kind})`);
  }
  return hits.join(", ");
}
