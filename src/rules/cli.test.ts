import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPermissionPolicy } from "../core/index.js";
import { defaultRulesCliIo, runRulesCli, type RulesCliIo } from "./cli.js";
import {
  assertFirestoreRulesUpToDate,
  extractLanyardRulesBlock,
  generateFirestoreRules,
  LANYARD_RULES_BEGIN,
  LANYARD_RULES_END,
  replaceLanyardRulesBlock
} from "./index.js";

type Role = "member" | "lead";
type Cap = "manage_members";

const policy = createPermissionPolicy<Role, Cap>({
  roles: { member: {}, lead: { inherits: ["member"], capabilities: ["manage_members"] } },
  staffCapability: "manage_members"
});

function rulesFile(block: string): string {
  return `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    ${LANYARD_RULES_BEGIN}
${block}    ${LANYARD_RULES_END}

    match /appData/{docId} {
      allow read: if request.auth != null;
    }
  }
}
`;
}

describe("Lanyard rules block helpers", () => {
  it("replaces only the text between the markers, idempotently", () => {
    const original = rulesFile("    // stale\n");
    const updated = replaceLanyardRulesBlock(original, generateFirestoreRules(policy));
    expect(extractLanyardRulesBlock(updated)).toBe(generateFirestoreRules(policy));
    expect(updated).toContain("match /appData/{docId} {");
    expect(updated.startsWith("rules_version = '2';")).toBe(true);
    expect(replaceLanyardRulesBlock(updated, generateFirestoreRules(policy))).toBe(updated);
  });

  it("rejects files with missing, duplicated, or misordered markers", () => {
    expect(() => extractLanyardRulesBlock("service cloud.firestore {}")).toThrow(/exactly one/);
    expect(() => extractLanyardRulesBlock(`${LANYARD_RULES_END}\n${LANYARD_RULES_BEGIN}\n`)).toThrow(/exactly one/);
    expect(() =>
      extractLanyardRulesBlock(
        `${LANYARD_RULES_BEGIN}\n${LANYARD_RULES_END}\n${LANYARD_RULES_BEGIN}\n${LANYARD_RULES_END}\n`
      )
    ).toThrow(/exactly one/);
  });

  it("detects stale rules after a policy change, ignoring line endings and trailing whitespace", () => {
    const current = rulesFile(generateFirestoreRules(policy));
    expect(() => assertFirestoreRulesUpToDate(current, policy)).not.toThrow();
    expect(() => assertFirestoreRulesUpToDate(current.replace(/\n/g, "  \r\n"), policy)).not.toThrow();

    // A new role holding the staff capability changes the generated role lists
    const widened = createPermissionPolicy<Role | "director", Cap>({
      roles: {
        member: {},
        lead: { inherits: ["member"], capabilities: ["manage_members"] },
        director: { inherits: ["lead"] }
      },
      staffCapability: "manage_members"
    });
    expect(() => assertFirestoreRulesUpToDate(current, widened)).toThrow(
      /out of date with the policy \(first difference at line \d+[\s\S]*expected: .*'director', 'lead'/
    );
    // So do different collection names
    expect(() => assertFirestoreRulesUpToDate(current, policy, { scopeCollection: "campaigns" })).toThrow(
      /out of date/
    );
  });
});

describe("lanyard-rules CLI", () => {
  let dir: string;
  let out: string[];
  let err: string[];
  let io: RulesCliIo;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "lanyard-rules-"));
    out = [];
    err = [];
    io = {
      ...defaultRulesCliIo,
      loadModule: async (path) => {
        if (path !== "./policy.js") throw new Error(`Cannot find module '${path}'`);
        return { appPolicy: policy, notAPolicy: { roles: {} } };
      },
      stdout: (text) => out.push(text),
      stderr: (text) => err.push(text)
    };
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("prints the generated block with the given collection names", async () => {
    expect(await runRulesCli(["--policy", "./policy.js", "--export", "appPolicy", "--scopes", "campaigns"], io)).toBe(
      0
    );
    expect(out.join("")).toBe(generateFirestoreRules(policy, { scopeCollection: "campaigns" }));
    expect(err).toEqual([]);
  });

  it("writes the block into a rules file, then checks it", async () => {
    const path = join(dir, "firestore.rules");
    await writeFile(path, rulesFile("    // stale\n"));
    expect(await runRulesCli(["--policy", "./policy.js", "--export", "appPolicy", "--check", path], io)).toBe(1);
    expect(err.join("")).toMatch(/firestore\.rules: The Lanyard rules block is out of date/);
    expect(err.join("")).not.toMatch(/Usage:/);

    expect(await runRulesCli(["--policy", "./policy.js", "--export", "appPolicy", "--write", path], io)).toBe(0);
    expect(out.at(-1)).toMatch(/Updated the Lanyard rules/);
    const written = await readFile(path, "utf8");
    expect(extractLanyardRulesBlock(written)).toBe(generateFirestoreRules(policy));
    expect(written).toContain("match /appData/{docId} {");

    expect(await runRulesCli(["--policy", "./policy.js", "--export", "appPolicy", "--write", path], io)).toBe(0);
    expect(out.at(-1)).toMatch(/already up to date/);
    expect(await runRulesCli(["--policy", "./policy.js", "--export", "appPolicy", "--check", path], io)).toBe(0);
    expect(out.at(-1)).toMatch(/are up to date/);
  });

  it("reports usage errors with a non-zero exit code", async () => {
    const run = async (argv: string[]) => {
      err = [];
      const code = await runRulesCli(argv, io);
      return { code, message: err.join("") };
    };
    expect(await run([])).toMatchObject({ code: 1, message: expect.stringMatching(/--policy is required/) });
    expect(await run(["--policy", "./policy.js"])).toMatchObject({
      code: 1,
      message: expect.stringMatching(/Export 'default' of \.\/policy\.js isn't a PermissionPolicy/)
    });
    expect(await run(["--policy", "./policy.js", "--export", "notAPolicy"])).toMatchObject({
      code: 1,
      message: expect.stringMatching(/isn't a PermissionPolicy/)
    });
    expect(await run(["--policy", "./missing.js"])).toMatchObject({
      code: 1,
      message: expect.stringMatching(/Cannot find module/)
    });
    expect(await run(["--policy", "./policy.js", "--bogus", "x"])).toMatchObject({
      code: 1,
      message: expect.stringMatching(/Unknown option '--bogus'/)
    });
    expect(await run(["--policy"])).toMatchObject({ code: 1, message: expect.stringMatching(/Invalid argument/) });
    expect(
      await run(["--policy", "./policy.js", "--export", "appPolicy", "--write", "a", "--check", "b"])
    ).toMatchObject({ code: 1, message: expect.stringMatching(/either --write or --check/) });
    expect(await runRulesCli(["--help"], io)).toBe(0);
    expect(out.at(-1)).toMatch(/^Usage: lanyard-rules/);
  });
});
