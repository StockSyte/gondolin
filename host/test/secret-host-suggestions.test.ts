import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import test from "node:test";

import { __test as suggestionTest } from "../src/secret-host-suggestions.ts";

const {
  collectSuggestionsFromDetectorSource,
  collectSuggestionsFromFile,
  extractHosts,
  extractUrlHosts,
  mergeSuggestions,
  parseTrufflehogJsonLines,
} = suggestionTest;

test("extractHosts finds urls and bare hostnames", () => {
  assert.deepEqual(extractHosts("see https://api.github.com/user and github.com"), [
    "api.github.com",
    "github.com",
  ]);
});

test("extractUrlHosts only finds url hosts", () => {
  assert.deepEqual(
    extractUrlHosts('import "github.com/x/y" and https://api.openai.com/v1/me'),
    ["api.openai.com"],
  );
});

test("collectSuggestionsFromFile finds host evidence near secret value", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-secret-hosts-"));
  const filePath = path.join(root, "sample.ts");

  try {
    fs.writeFileSync(
      filePath,
      [
        'const baseUrl = "https://api.github.com";',
        'const token = "secret-value";',
        'fetch(`${baseUrl}/user`, { headers: { authorization: `Bearer ${token}` } });',
      ].join("\n"),
    );

    const suggestions = collectSuggestionsFromFile(root, filePath, "secret-value");
    assert.equal(suggestions.length, 1);
    assert.equal(suggestions[0].host, "api.github.com");
    assert.equal(suggestions[0].file, "sample.ts");
    assert.equal(suggestions[0].line, 2);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("parseTrufflehogJsonLines parses newline-delimited json", () => {
  const findings = parseTrufflehogJsonLines(
    '{"DetectorName":"OpenAI"}\n{"DetectorName":"Github"}\n',
  );
  assert.deepEqual(findings.map((finding: any) => finding.DetectorName), [
    "OpenAI",
    "Github",
  ]);
});

test("collectSuggestionsFromDetectorSource finds hosts in detector source", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-detector-src-"));
  const detectorDir = path.join(root, "pkg", "detectors", "openai");
  fs.mkdirSync(detectorDir, { recursive: true });
  fs.writeFileSync(
    path.join(detectorDir, "openai.go"),
    [
      'package openai',
      'import "github.com/wasilibs/go-re2"',
      'func x() { _ = detectorspb.DetectorType_OpenAI }',
      'const endpoint = "https://api.openai.com/v1/me"',
    ].join("\n"),
  );

  try {
    const suggestions = collectSuggestionsFromDetectorSource(root, "OpenAI");
    assert.equal(suggestions.length, 1);
    assert.equal(suggestions[0].host, "api.openai.com");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("mergeSuggestions deduplicates hosts and counts evidence", () => {
  const merged = mergeSuggestions([
    {
      host: "api.github.com",
      file: "a.ts",
      line: 1,
      snippet: "one",
      count: 1,
    },
    {
      host: "api.github.com",
      file: "b.ts",
      line: 2,
      snippet: "two",
      count: 1,
    },
  ]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].host, "api.github.com");
  assert.equal(merged[0].count, 2);
});
