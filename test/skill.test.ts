import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { catalog } from "../src/findings.js";

const ref = (file: string) => readFileSync(`skill/supabase-security/references/${file}`, "utf8");

describe("skill references", () => {
  it("has a section for every finding the CLI can report", () => {
    for (const [id, entry] of Object.entries(catalog)) {
      const [file, section] = entry.ref.split("#");
      expect(ref(file!), `${id} -> ${entry.ref}`).toMatch(new RegExp(`^## ${section}$`, "m"));
    }
  });

  it("maps every SQL audit check in SKILL.md", () => {
    const skill = readFileSync("skill/supabase-security/SKILL.md", "utf8");
    const checks = [...readFileSync("sql/audit.sql", "utf8").matchAll(/'(sql\.[a-z_]+)'/g)].map((m) => m[1]!);
    for (const check of new Set(checks)) expect(skill, check).toContain(check);
  });
});
