// Storage can throw (private windows, blocked site data), so every access is
// guarded and the app works without it.

function read(storage: () => Storage, key: string): string | null {
  try {
    return storage().getItem(key);
  } catch {
    return null;
  }
}

function write(storage: () => Storage, key: string, value: string | null): void {
  try {
    if (value === null) storage().removeItem(key);
    else storage().setItem(key, value);
  } catch {
    // Not persisted; the value lasts until the page reloads.
  }
}

const TOKEN = "dns-api-token";
const API_URL = "dns-api-url";

/** The token stays in this tab only. */
export const savedToken = () => read(() => sessionStorage, TOKEN);
export const saveToken = (token: string | null) => write(() => sessionStorage, TOKEN, token);

/** The API address is not secret, so it is remembered across visits. */
export const savedApiUrl = () => read(() => localStorage, API_URL);
export const saveApiUrl = (url: string | null) => write(() => localStorage, API_URL, url);
