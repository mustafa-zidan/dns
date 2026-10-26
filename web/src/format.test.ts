import { describe, expect, it } from "vitest";
import { duration, parseApiUrl, percent } from "./format";

describe("duration", () => {
  it("shows the two largest units", () => {
    expect(duration(0)).toBe("0s");
    expect(duration(59)).toBe("59s");
    expect(duration(61)).toBe("1m 1s");
    expect(duration(3 * 3600 + 12 * 60 + 5)).toBe("3h 12m");
    expect(duration(2 * 86400 + 5 * 3600)).toBe("2d 5h");
  });

  it("clamps negative and fractional input", () => {
    expect(duration(-5)).toBe("0s");
    expect(duration(9.9)).toBe("9s");
  });
});

describe("percent", () => {
  it("keeps one decimal", () => {
    expect(percent(0.70454)).toBe("70.5%");
    expect(percent(0)).toBe("0.0%");
  });
});

describe("parseApiUrl", () => {
  it("accepts http and https and drops trailing slashes", () => {
    expect(parseApiUrl(" http://127.0.0.1:8053/ ")).toBe("http://127.0.0.1:8053");
    expect(parseApiUrl("https://dns.lan/proxy/")).toBe("https://dns.lan/proxy");
  });

  it("rejects anything else", () => {
    expect(parseApiUrl("127.0.0.1:8053")).toBeNull();
    expect(parseApiUrl("javascript:alert(1)")).toBeNull();
    expect(parseApiUrl("")).toBeNull();
  });
});
