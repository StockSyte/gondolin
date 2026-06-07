import assert from "node:assert/strict";
import test from "node:test";

import { createHttpHooks } from "../src/http/hooks.ts";
import { __test } from "../src/vm/core.ts";

test("runtime secret env merge removes deleted startup secrets and adds new ones", () => {
  const { env, secretManager } = createHttpHooks({
    secrets: {
      API_KEY: {
        hosts: ["example.com"],
        value: "secret-value",
      },
    },
  });

  secretManager.deleteSecret("API_KEY");
  secretManager.addSecret("OTHER_KEY", {
    hosts: ["example.org"],
    value: "other-secret",
  });

  const merged = __test.mergeExecEnvWithRuntimeSecrets(env, secretManager);
  assert.ok(merged);
  assert.equal(merged.some((entry: string) => entry.startsWith("API_KEY=")), false);
  assert.equal(
    merged.some((entry: string) => entry.startsWith("OTHER_KEY=")),
    true,
  );
});

test("runtime secret env file serializes placeholder exports", () => {
  const text = __test.serializeSecretsEnvFile({
    OPENAI_API_KEY: "GONDOLIN_SECRET_abc123",
  });

  assert.equal(
    text,
    "export OPENAI_API_KEY='GONDOLIN_SECRET_abc123'\n",
  );
});
