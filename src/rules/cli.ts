import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { PermissionPolicy } from "../core/index.js";
import {
  assertFirestoreRulesUpToDate,
  generateFirestoreRules,
  replaceLanyardRulesBlock,
  type FirestoreRulesOptions
} from "./index.js";

const USAGE = `Usage: lanyard-rules --policy <module.js> [--export <name>] [options]

Generates the Lanyard Firestore security rules for a PermissionPolicy.

  --policy <path>        Compiled JS module exporting the policy (required)
  --export <name>        Name of the exported policy (default: "default")
  --users <name>         usersCollection (default: "users")
  --scopes <name>        scopeCollection (default: "workspaces")
  --members <name>       membersSubcollection (default: "members")
  --meta <name>          metaCollection, Lanyard's metadata (default: "lanyard_meta")
  --require-verified-email <true|false>
                         Require email_verified for signed-in access (default: true)
  --write <rules file>   Replace the block between the lanyard-rules markers in this file
  --check <rules file>   Exit with an error if that block is out of date
  (with neither --write nor --check, the generated block is printed)
`;

/** A failure that isn't a usage mistake, so the CLI reports it without the usage text. */
class RulesCliError extends Error {}

/** Side effects the CLI needs, injectable for tests. */
export interface RulesCliIo {
  loadModule(path: string): Promise<Record<string, unknown>>;
  readFile(path: string): Promise<string>;
  writeFile(path: string, contents: string): Promise<void>;
  stdout(text: string): void;
  stderr(text: string): void;
}

export const defaultRulesCliIo: RulesCliIo = {
  loadModule: (path) => import(pathToFileURL(resolve(path)).href),
  readFile: (path) => readFile(path, "utf8"),
  writeFile: (path, contents) => writeFile(path, contents, "utf8"),
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text)
};

function parseBooleanFlag(value: string | undefined, flag: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${flag} must be 'true' or 'false'`);
}

function parseArgs(argv: readonly string[]): Map<string, string> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--help" || flag === "-h") {
      args.set("help", "true");
      continue;
    }
    const value = argv[i + 1];
    if (!flag.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`Invalid argument '${flag}'`);
    }
    args.set(flag.slice(2), value);
    i++;
  }
  const known = new Set([
    "help",
    "policy",
    "export",
    "users",
    "scopes",
    "members",
    "meta",
    "require-verified-email",
    "write",
    "check"
  ]);
  for (const key of args.keys()) {
    if (!known.has(key)) throw new Error(`Unknown option '--${key}'`);
  }
  if (args.has("write") && args.has("check")) throw new Error("Use either --write or --check, not both");
  return args;
}

function isPermissionPolicy(value: unknown): value is PermissionPolicy<string, string> {
  const candidate = value as Partial<PermissionPolicy<string, string>> | null;
  return Boolean(
    candidate &&
    typeof candidate === "object" &&
    candidate.roles &&
    typeof candidate.isStaff === "function" &&
    typeof candidate.hasCapability === "function" &&
    candidate.cardFields
  );
}

/** Runs the `lanyard-rules` CLI, returning the process exit code. */
export async function runRulesCli(argv: readonly string[], io: RulesCliIo = defaultRulesCliIo): Promise<number> {
  try {
    const args = parseArgs(argv);
    if (args.has("help")) {
      io.stdout(USAGE);
      return 0;
    }
    const policyPath = args.get("policy");
    if (!policyPath) throw new Error("--policy is required");
    const exportName = args.get("export") ?? "default";
    const policyModule = await io.loadModule(policyPath);
    const policy = policyModule[exportName];
    if (!isPermissionPolicy(policy)) {
      throw new Error(`Export '${exportName}' of ${policyPath} isn't a PermissionPolicy (from createPermissionPolicy)`);
    }
    const options: FirestoreRulesOptions = {
      usersCollection: args.get("users"),
      scopeCollection: args.get("scopes"),
      membersSubcollection: args.get("members"),
      metaCollection: args.get("meta"),
      requireVerifiedEmail: parseBooleanFlag(args.get("require-verified-email"), "--require-verified-email")
    };

    const checkPath = args.get("check");
    if (checkPath) {
      const rulesText = await io.readFile(checkPath);
      try {
        assertFirestoreRulesUpToDate(rulesText, policy, options);
      } catch (error) {
        throw new RulesCliError(`${checkPath}: ${(error as Error).message}`);
      }
      io.stdout(`Lanyard rules in ${checkPath} are up to date.\n`);
      return 0;
    }
    const generated = generateFirestoreRules(policy, options);
    const writePath = args.get("write");
    if (writePath) {
      const current = await io.readFile(writePath);
      const updated = replaceLanyardRulesBlock(current, generated);
      if (updated === current) {
        io.stdout(`Lanyard rules in ${writePath} were already up to date.\n`);
      } else {
        await io.writeFile(writePath, updated);
        io.stdout(`Updated the Lanyard rules in ${writePath}.\n`);
      }
      return 0;
    }
    io.stdout(generated);
    return 0;
  } catch (error) {
    const message = (error as Error).message;
    io.stderr(error instanceof RulesCliError ? `lanyard-rules: ${message}\n` : `lanyard-rules: ${message}\n\n${USAGE}`);
    return 1;
  }
}
