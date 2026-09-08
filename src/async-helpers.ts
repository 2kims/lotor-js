export interface Page<T> { items: readonly T[]; nextCursor: string | null }
export interface PageOptions { signal?: AbortSignal; maxPages?: number }
export interface PollOptions { signal?: AbortSignal; maxAttempts?: number; intervalMs?: number }

function bound(value: number, name: string, maximum: number, minimum = 1): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  return value;
}

/** Lazy bounded iteration; errors propagate without retrying or changing authority. */
export async function* iteratePages<T>(read: (cursor: string | undefined, signal?: AbortSignal) => Promise<Page<T>>, options: PageOptions = {}): AsyncGenerator<T> {
  const maximum = bound(options.maxPages ?? 100, "maxPages", 10000);
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < maximum; pageNumber++) {
    options.signal?.throwIfAborted();
    const page = await read(cursor, options.signal);
    options.signal?.throwIfAborted();
    if (page.nextCursor !== null && (page.nextCursor === "" || seen.has(page.nextCursor))) throw new Error("Lotor returned an invalid or repeated cursor");
    for (const item of page.items) { options.signal?.throwIfAborted(); yield item; }
    if (page.nextCursor === null) return;
    seen.add(page.nextCursor);
    cursor = page.nextCursor;
  }
  throw new Error("Lotor pagination exceeded maxPages");
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); signal?.removeEventListener("abort", abort); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

/** Returns the terminal operation, including failed/cancelled; callers inspect status. */
export async function pollOperation<T extends { status: string }>(read: (signal?: AbortSignal) => Promise<T>, options: PollOptions = {}): Promise<T> {
  const maximum = bound(options.maxAttempts ?? 120, "maxAttempts", 10000);
  const interval = bound(options.intervalMs ?? 500, "intervalMs", 60000, 0);
  for (let attempt = 0; attempt < maximum; attempt++) {
    options.signal?.throwIfAborted();
    const operation = await read(options.signal);
    options.signal?.throwIfAborted();
    if (["succeeded", "failed", "cancelled"].includes(operation.status)) return operation;
    if (operation.status !== "pending" && operation.status !== "running") throw new Error("Lotor returned an unknown operation status");
    if (attempt + 1 < maximum) await delay(interval, options.signal);
  }
  throw new Error("Lotor operation exceeded maxAttempts");
}
