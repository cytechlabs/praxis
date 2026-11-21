import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

/**
 * Browser handling of file-transfer downloads (PRA-429).
 *
 * Drives real Chromium against the download harness
 * (backend/tests/helpers/file_transfer_harness.py), which serves the actual
 * file-transfer route over HTTP with disposable SSH and agent fixtures. It
 * needs no Praxis stack and no sign-in, so it lives in the `unit` project.
 *
 *   python -m tests.helpers.file_transfer_harness --port 8429
 *   DOWNLOAD_HARNESS_URL=http://127.0.0.1:8429 \
 *     npx playwright test --project=unit download-truthfulness
 *
 * To check the same behavior through the production hops (ingress and
 * frontend proxy), point DOWNLOAD_HARNESS_URL at the ingress and set
 * DOWNLOAD_HARNESS_PREFIX=/api/backend with the harness reachable as the
 * proxy's backend.
 *
 * The file manager starts a download with window.open on the download URL, so
 * the spec does the same. A complete file must reach the download manager
 * intact; a failure before the first byte must be an error page, never a
 * download; a failure after the 200 must be a failed download, never a clean
 * short file.
 */

const ORIGIN = process.env.DOWNLOAD_HARNESS_URL;
// Set to /api/backend to go through the frontend proxy and ingress.
const API = ORIGIN ? `${ORIGIN}${process.env.DOWNLOAD_HARNESS_PREFIX ?? ""}` : "";
const SSH = 1;
const AGENT = 2;
const MIB = 1024 * 1024;

const url = (system: number, path: string) =>
  `${API}/transfer/${system}/download?path=${encodeURIComponent(path)}`;

type Outcome =
  | { kind: "download"; failure: string | null; file: string; filename: string }
  | { kind: "page"; status: number; body: string };

/**
 * Open a download URL the way the UI does and report what the browser did.
 * A download started from window.open is reported on the opener page and its
 * popup closes; an error response stays in the popup as a rendered page.
 */
async function open(
  context: BrowserContext,
  opener: Page,
  target: string,
): Promise<Outcome> {
  let status = 0;
  const onResponse = (res: { url(): string; status(): number }) => {
    if (res.url() === target) status = res.status();
  };
  context.on("response", onResponse);
  const result = new Promise<Outcome>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no browser outcome")), 20_000);
    opener.once("download", async (download) => {
      clearTimeout(timer);
      const failure = await download.failure();
      const file = failure ? "" : await download.path();
      resolve({
        kind: "download",
        failure,
        file: file ?? "",
        filename: download.suggestedFilename(),
      });
    });
    context.once("page", (popup) => {
      popup.once("load", async () => {
        clearTimeout(timer);
        resolve({
          kind: "page",
          status,
          body: (await popup.locator("body").innerText()).trim(),
        });
      });
    });
  });
  try {
    await opener.evaluate((u) => window.open(u, "_blank"), target);
    return await result;
  } finally {
    context.off("response", onResponse);
  }
}

async function state(opener: Page) {
  const res = await opener.request.get(`${API}/__state`);
  return res.json();
}

async function settledAudit(opener: Page) {
  for (let i = 0; i < 100; i++) {
    const s = await state(opener);
    if (s.audits.length && s.audits.every((a: any) => a.status !== "in_progress")) {
      return s;
    }
    await opener.waitForTimeout(100);
  }
  throw new Error("audit never settled");
}

test.describe("file download truthfulness in the browser", () => {
  test.skip(!ORIGIN, "set DOWNLOAD_HARNESS_URL to a running download harness");

  let opener: Page;
  test.beforeEach(async ({ page }) => {
    opener = page;
    await page.request.post(`${API}/__reset`);
    await page.goto(`${API}/__state`);
  });

  for (const [name, system] of [
    ["ssh", SSH],
    ["agent", AGENT],
  ] as const) {
    test(`${name}: a complete file is saved intact and audited as success`, async ({
      context,
    }) => {
      const out = await open(context, opener, url(system, "/ok/medium.bin"));
      expect(out.kind).toBe("download");
      if (out.kind !== "download") return;
      expect(out.failure).toBeNull();
      expect(out.filename).toBe("medium.bin");
      const size = 5 * MIB + 3;
      expect(statSync(out.file).size).toBe(size);
      const s = await settledAudit(opener);
      expect(createHash("sha256").update(readFileSync(out.file)).digest("hex")).toBe(
        s.sha256["/ok/medium.bin"],
      );
      expect(s.audits[0]).toMatchObject({ status: "success", size_bytes: size });
    });

    test(`${name}: a zero-byte file is a successful empty download`, async ({
      context,
    }) => {
      const out = await open(context, opener, url(system, "/ok/empty.bin"));
      expect(out.kind).toBe("download");
      if (out.kind !== "download") return;
      expect(out.failure).toBeNull();
      expect(statSync(out.file).size).toBe(0);
      expect((await settledAudit(opener)).audits[0].status).toBe("success");
    });

    for (const [path, status] of [
      ["/missing/file", 404],
      ["/err/denied.bin", 403],
      ["/err/dir", 400],
    ] as const) {
      test(`${name}: ${path} is an error page, not a download`, async ({
        context,
      }) => {
        const out = await open(context, opener, url(system, path));
        expect(out.kind).toBe("page");
        if (out.kind !== "page") return;
        expect(out.status).toBe(status);
        expect(out.body).toContain("detail");
        expect((await settledAudit(opener)).audits[0].status).toBe("error");
      });
    }
  }

  test("ssh: a failure after the 200 is a failed download", async ({ context }) => {
    const out = await open(context, opener, url(SSH, "/err/midstream.bin"));
    expect(out.kind).toBe("download");
    if (out.kind !== "download") return;
    expect(out.failure).not.toBeNull();
    const s = await settledAudit(opener);
    expect(s.audits[0]).toMatchObject({ status: "error", sha256: null });
    expect(s.leaked).toBe(0);
  });

  test("ssh: a failure on an unsized stream is a failed download", async ({
    context,
  }) => {
    const out = await open(context, opener, url(SSH, "/err/midstream-chunked.bin"));
    expect(out.kind).toBe("download");
    if (out.kind !== "download") return;
    expect(out.failure).not.toBeNull();
    expect((await settledAudit(opener)).audits[0].status).toBe("error");
  });

  test("ssh: a host that ends early is a failed download", async ({ context }) => {
    const out = await open(context, opener, url(SSH, "/err/short.bin"));
    expect(out.kind).toBe("download");
    if (out.kind !== "download") return;
    expect(out.failure).not.toBeNull();
    expect((await settledAudit(opener)).audits[0].error).toContain("incomplete");
  });

  test("agent: a failure during the transfer is an error page, not a download", async ({
    context,
  }) => {
    const out = await open(context, opener, url(AGENT, "/err/midstream.bin"));
    expect(out.kind).toBe("page");
    if (out.kind !== "page") return;
    expect(out.status).toBe(502);
    const s = await settledAudit(opener);
    expect(s.audits[0]).toMatchObject({ status: "error", transport: "agent" });
    expect(s.spool_files).toEqual([]);
  });

  test("cancelling a download in the browser releases the host", async () => {
    const started = opener.waitForEvent("download");
    await opener.evaluate(
      (u) => window.open(u, "_blank"),
      url(SSH, "/big/endless.bin"),
    );
    const download = await started;
    await download.cancel();
    const s = await settledAudit(opener);
    expect(s.audits[0]).toMatchObject({
      status: "error",
      error: "client_disconnected",
    });
    expect(s.leaked).toBe(0);
  });
});
