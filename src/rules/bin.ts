#!/usr/bin/env node
import { runRulesCli } from "./cli.js";

process.exitCode = await runRulesCli(process.argv.slice(2));
