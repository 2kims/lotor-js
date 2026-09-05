import type { TokenStore } from "./types.js";
export type BrowserFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export declare class LotorBrowserError extends Error {
    readonly status: number;
    readonly code: string;
    constructor(message: string, status: number, code: string);
}
export interface BrowserRequestTransport {
    request<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<T>;
    requestWithMetadata<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<{
        body: T;
        headers: Headers;
    }>;
}
export declare class BrowserTransport {
    private readonly baseUrl;
    private readonly fetcher;
    private readonly tokenStore;
    private readonly publishableKey;
    constructor(baseUrl: string, fetcher: BrowserFetch, tokenStore: TokenStore, publishableKey: string);
    request<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<T>;
    requestWithMetadata<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<{
        body: T;
        headers: Headers;
    }>;
}
export type CSRFTokenProvider = () => string | null | Promise<string | null>;
/** Cookie-authenticated transport for a Lotor gateway mounted on the application origin. */
export declare class SameOriginBrowserTransport implements BrowserRequestTransport {
    private readonly fetcher;
    private readonly publishableKey;
    private readonly csrfToken;
    constructor(fetcher: BrowserFetch, publishableKey: string, csrfToken?: CSRFTokenProvider);
    request<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<T>;
    requestWithMetadata<T>(path: string, init?: RequestInit, authenticated?: boolean): Promise<{
        body: T;
        headers: Headers;
    }>;
}
