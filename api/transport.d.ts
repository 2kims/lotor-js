import type { TokenStore } from "./types.js";
export type BrowserFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export declare class LotorBrowserError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(message: string, status: number, code: string);
}
export declare class BrowserTransport {
    private readonly baseUrl;
    private readonly fetcher;
    private readonly tokenStore;
    constructor(baseUrl: string, fetcher: BrowserFetch, tokenStore: TokenStore);
    request<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<T>;
}
