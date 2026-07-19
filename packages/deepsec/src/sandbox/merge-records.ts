import fs from "node:fs";
import path from "node:path";
import { type AnalysisEntry, type FileRecord, type Finding, fileRecordSchema } from "@deepsec/core";

/**
 * Tarball extraction is `cwd=dataDir(projectId)`, so file records live
 * under `<destDir>/files/**.json`. We only merge those — run metadata
 * (`runs/*.json`) is unique per runId, so the tar overwrite is safe there.
 */
const FILES_SUBDIR = "files";

/**
 * Return true for tarball entry paths the merge machinery cares about:
 * file records under `files/**.json`. Run metadata (`runs/*.json`) is
 * unique per runId, so the tar overwrite is safe there and needs no merge.
 */
export function isFileRecordPath(rel: string): boolean {
  const norm = rel.replaceAll("\\", "/");
  return norm.startsWith(`${FILES_SUBDIR}/`) && norm.endsWith(".json");
}

/**
 * Snapshot the existing file records at the given `destDir`-relative paths
 * (e.g. `"files/src/foo.ts.json"`) into a map keyed by that path.
 *
 * Called BEFORE tar extraction, with the tarball's own entry list, so we
 * have the host's pre-extraction state to merge against once the tarball
 * lands. Deliberately NOT a full walk of `files/**`: projects can hold
 * tens of thousands of records (~150MB heap per full snapshot), and the
 * streaming download loop runs this per sandbox — full snapshots stacked
 * across 30 concurrent loops are what OOM'd the orchestrator.
 *
 * Best-effort: missing files and malformed JSON are skipped silently
 * rather than aborting the download — a corrupt or absent host record
 * shouldn't block a sandbox upload, and the incoming version will replace
 * it via the normal extract path.
 */
export function snapshotFileRecords(
  destDir: string,
  relPaths: Iterable<string>,
): Map<string, FileRecord> {
  const out = new Map<string, FileRecord>();
  for (const rel of relPaths) {
    if (!isFileRecordPath(rel)) continue;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(destDir, rel), "utf-8"));
      out.set(rel, raw as FileRecord);
    } catch {
      // missing or malformed — nothing to merge against
    }
  }
  return out;
}

/**
 * Merge two FileRecords representing the same file but written by
 * concurrent sandbox uploads.
 *
 * The race we're fixing: sandbox A and sandbox B both snapshotted the
 * host data dir at slightly different times. Each appended its own
 * `analysisHistory` entry locally, then uploaded a full tarball. Without
 * merging, whichever tarball is extracted last overwrites the other's
 * history — and in practice we observed entire codex runs disappearing
 * from per-file `analysisHistory` despite being recorded in `runs/*.json`.
 *
 * Merge strategy:
 *   - `analysisHistory`: union by `runId` (each run is globally unique).
 *     For the same runId on both sides, prefer `incoming` since the
 *     tarball is the more recent serialization.
 *   - `findings`: union by `(vulnSlug, normalized title)` signature, the
 *     same key `process()` uses to dedupe re-runs. For matching findings,
 *     merge field-by-field so a `revalidation` / `triage` set on either
 *     side survives.
 *   - `gitInfo`: prefer whichever side has it set — enrich runs only
 *     populate, never clear, so losing it across an extract is real loss.
 *   - `status`: "analyzed" wins over anything else (a finished run on
 *     either side means the file is analyzed). Otherwise prefer incoming.
 *   - `lockedByRunId` / `lockedAt`: prefer incoming; the per-batch loop
 *     in `process()` is the authoritative writer.
 *   - Scan-time fields (`candidates`, `lastScannedAt`, `lastScannedRunId`,
 *     `fileHash`): prefer incoming. Concurrent process/revalidate runs
 *     don't touch these — if they differ, the difference came from a
 *     scan run that has its own non-racing lifecycle.
 */
export function mergeFileRecord(host: FileRecord, incoming: FileRecord): FileRecord {
  const historyByRunId = new Map<string, AnalysisEntry>();
  for (const entry of host.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  for (const entry of incoming.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  const mergedHistory = Array.from(historyByRunId.values()).sort(
    (a, b) => new Date(a.investigatedAt).getTime() - new Date(b.investigatedAt).getTime(),
  );

  const findingsBySig = new Map<string, Finding>();
  for (const f of host.findings ?? []) {
    findingsBySig.set(findingSignature(f), f);
  }
  for (const f of incoming.findings ?? []) {
    const sig = findingSignature(f);
    const existing = findingsBySig.get(sig);
    findingsBySig.set(sig, existing ? mergeFinding(existing, f) : f);
  }
  const mergedFindings = Array.from(findingsBySig.values());

  const status =
    host.status === "analyzed" || incoming.status === "analyzed" ? "analyzed" : incoming.status;

  return {
    ...incoming,
    gitInfo: incoming.gitInfo ?? host.gitInfo,
    findings: mergedFindings,
    analysisHistory: mergedHistory,
    status,
  };
}

function findingSignature(f: Finding): string {
  return `${f.vulnSlug ?? ""}::${(f.title ?? "").trim().toLowerCase()}`;
}

function mergeFinding(host: Finding, incoming: Finding): Finding {
  return {
    ...host,
    ...incoming,
    revalidation: incoming.revalidation ?? host.revalidation,
    triage: incoming.triage ?? host.triage,
    producedByRunId: host.producedByRunId ?? incoming.producedByRunId,
  };
}

/**
 * After tar extraction, validate every file record the tarball wrote
 * (`relPaths` — the same entry list the pre-extract validation pass
 * produced) and re-write any that also existed in `hostSnapshot` with a
 * merged version. Records not in the tarball were not touched by the
 * extract and are left alone — walking the whole tree here would re-parse
 * and re-validate the entire project dataset on every streaming poll.
 *
 * Sandbox output is the trust boundary, so every incoming record must:
 *   - parse as JSON
 *   - match `fileRecordSchema` exactly
 *   - declare the same `projectId` as the destDir's basename
 *   - declare a `filePath` whose serialized form matches the tarball entry
 *     path (`files/<filePath>.json`)
 *
 * If any of those checks fail on a record that *also* existed on the host,
 * we restore the host's version on disk — better an out-of-date but valid
 * record than a corrupted/spoofed one. If the failing record didn't exist
 * on the host, we delete it (the sandbox didn't have a legitimate need to
 * write a malformed record there).
 *
 * Files that didn't exist on the host before extraction and pass validation
 * are left untouched (they're the sandbox's contribution). Files that
 * existed on the host but are missing from the tarball are also untouched
 * (the sandbox didn't change them this poll).
 *
 * Returns the number of records that were merge-rewritten.
 */
export function mergeAfterExtract(
  destDir: string,
  hostSnapshot: Map<string, FileRecord>,
  expectedProjectId: string | undefined,
  relPaths: Iterable<string>,
): number {
  const requireProjectId = expectedProjectId ?? path.basename(destDir);

  let merged = 0;
  for (const relRaw of relPaths) {
    if (!isFileRecordPath(relRaw)) continue;
    const rel = relRaw.replaceAll("\\", "/");
    const full = path.join(destDir, rel);
    const host = hostSnapshot.get(relRaw) ?? hostSnapshot.get(rel);

    let raw: string;
    try {
      raw = fs.readFileSync(full, "utf-8");
    } catch {
      // The tarball listed it but nothing landed on disk — nothing to do.
      continue;
    }

    let parsedRaw: unknown;
    try {
      parsedRaw = JSON.parse(raw);
    } catch {
      // Malformed JSON — restore host snapshot if we have one, else drop.
      restoreOrDrop(full, host);
      continue;
    }

    const parsed = fileRecordSchema.safeParse(parsedRaw);
    if (!parsed.success) {
      restoreOrDrop(full, host);
      continue;
    }
    const incoming = parsed.data;

    // Sandbox tarball came from `data/<projectId>/`, so every record in
    // it must claim that same projectId, and the on-disk path must match
    // its declared filePath.
    const expectedRel = path.join(FILES_SUBDIR, `${incoming.filePath}.json`).replaceAll("\\", "/");
    if (incoming.projectId !== requireProjectId || rel !== expectedRel) {
      restoreOrDrop(full, host);
      continue;
    }

    if (!host) continue;
    const out = mergeFileRecord(host, incoming);
    fs.writeFileSync(full, JSON.stringify(out, null, 2) + "\n");
    merged++;
  }
  return merged;
}

function restoreOrDrop(full: string, host: FileRecord | undefined): void {
  if (host) {
    try {
      fs.writeFileSync(full, JSON.stringify(host, null, 2) + "\n");
    } catch {}
    return;
  }
  try {
    fs.unlinkSync(full);
  } catch {}
}
