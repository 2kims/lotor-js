export interface Page<T> {
    items: readonly T[];
    nextCursor: string | null;
}
export interface PageOptions {
    signal?: AbortSignal;
    maxPages?: number;
}
export interface PollOptions {
    signal?: AbortSignal;
    maxAttempts?: number;
    intervalMs?: number;
}
/** Lazy bounded iteration; errors propagate without retrying or changing authority. */
export declare function iteratePages<T>(read: (cursor: string | undefined, signal?: AbortSignal) => Promise<Page<T>>, options?: PageOptions): AsyncGenerator<T>;
/** Returns the terminal operation, including failed/cancelled; callers inspect status. */
export declare function pollOperation<T extends {
    status: string;
}>(read: (signal?: AbortSignal) => Promise<T>, options?: PollOptions): Promise<T>;
