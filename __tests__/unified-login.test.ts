import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getMetaLoginMode, getMissingInstagramOAuthEnv } from "../lib/env";
import {
  getAssignedInstagramAccounts,
  getUserInfo,
  getUserMedia,
  isInstagramLoginToken,
  sendPrivateReply,
} from "../lib/meta/client";
import {
  exchangeUnifiedCodeForToken,
  getAuthorizationUrl,
} from "../lib/meta/oauth";

// Unified login (diwenne/openreply#104): apps created from October 2026 on
// only get Facebook Login for Business with a configuration, which returns a
// Facebook system-user token used on graph.facebook.com.

const IG_TOKEN = "IGAAtest";
const FB_TOKEN = "EAAtest";
const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const fetchMock = vi.fn();
const respond = (body: unknown, status = 200) =>
  fetchMock.mockResolvedValueOnce(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  );
const calledUrl = (n = 0) => new URL(String(fetchMock.mock.calls[n][0]));

beforeEach(() => {
  vi.unstubAllEnvs();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("login mode", () => {
  it("stays on Instagram Login unless a configuration ID is set", () => {
    vi.stubEnv("META_LOGIN_CONFIG_ID", "");
    expect(getMetaLoginMode()).toBe("instagram");
    vi.stubEnv("META_LOGIN_CONFIG_ID", "123");
    expect(getMetaLoginMode()).toBe("unified");
  });

  it("asks for the Facebook app credentials and configuration in unified mode", () => {
    vi.stubEnv("META_LOGIN_CONFIG_ID", "123");
    vi.stubEnv("ENCRYPTION_KEY", KEY);
    vi.stubEnv("NEXTAUTH_SECRET", "secret");
    vi.stubEnv("FACEBOOK_APP_ID", "");
    vi.stubEnv("FACEBOOK_APP_SECRET", "");
    vi.stubEnv("INSTAGRAM_APP_ID", "");
    expect(getMissingInstagramOAuthEnv()).toEqual([
      "FACEBOOK_APP_ID",
      "FACEBOOK_APP_SECRET",
    ]);
  });

  it("builds a Facebook dialog URL with config_id instead of scopes", () => {
    vi.stubEnv("META_LOGIN_CONFIG_ID", "cfg_1");
    vi.stubEnv("FACEBOOK_APP_ID", "fb_app");
    const url = new URL(getAuthorizationUrl("https://app.test/cb", "state_1"));
    expect(url.origin).toBe("https://www.facebook.com");
    expect(url.pathname).toMatch(/^\/v\d+\.\d+\/dialog\/oauth$/);
    expect(url.searchParams.get("client_id")).toBe("fb_app");
    expect(url.searchParams.get("config_id")).toBe("cfg_1");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.test/cb");
    expect(url.searchParams.get("state")).toBe("state_1");
    expect(url.searchParams.has("scope")).toBe(false);
  });

  it("keeps the Instagram authorize URL when no configuration is set", () => {
    vi.stubEnv("INSTAGRAM_APP_ID", "ig_app");
    const url = new URL(getAuthorizationUrl("https://app.test/cb", "s"));
    expect(url.origin).toBe("https://www.instagram.com");
  });
});

describe("unified code exchange", () => {
  beforeEach(() => {
    vi.stubEnv("FACEBOOK_APP_ID", "fb_app");
    vi.stubEnv("FACEBOOK_APP_SECRET", "fb_secret");
  });

  it("treats a system-user token without expiry as non-expiring", async () => {
    respond({ access_token: FB_TOKEN, token_type: "bearer" });
    expect(await exchangeUnifiedCodeForToken("code", "https://app.test/cb")).toEqual({
      accessToken: FB_TOKEN,
      expiresIn: null,
    });
    const url = calledUrl();
    expect(url.origin).toBe("https://graph.facebook.com");
    expect(url.pathname).toMatch(/\/oauth\/access_token$/);
    expect(url.searchParams.get("client_secret")).toBe("fb_secret");
  });

  it("keeps a real expiry when Meta sends one", async () => {
    respond({ access_token: FB_TOKEN, expires_in: 3600 });
    const { expiresIn } = await exchangeUnifiedCodeForToken("code", "uri");
    expect(expiresIn).toBe(3600);
  });

  it("surfaces Meta's error message", async () => {
    respond({ error: { message: "Invalid verification code format." } }, 400);
    await expect(exchangeUnifiedCodeForToken("bad", "uri")).rejects.toThrow(
      "Invalid verification code format."
    );
  });
});

describe("Graph host per token", () => {
  it("recognises Instagram Login tokens by their prefix", () => {
    expect(isInstagramLoginToken("IGAAabc")).toBe(true);
    expect(isInstagramLoginToken("IGQVabc")).toBe(true);
    expect(isInstagramLoginToken("EAAabc")).toBe(false);
  });

  it("sends Instagram Login tokens to graph.instagram.com", async () => {
    respond({ recipient_id: "r", message_id: "m" });
    await sendPrivateReply(IG_TOKEN, "ig_1", "comment_1", "hi");
    expect(calledUrl().origin).toBe("https://graph.instagram.com");
  });

  it("sends Unified login tokens to graph.facebook.com", async () => {
    respond({ recipient_id: "r", message_id: "m" });
    await sendPrivateReply(FB_TOKEN, "ig_1", "comment_1", "hi");
    const url = calledUrl();
    expect(url.origin).toBe("https://graph.facebook.com");
    expect(url.pathname).toMatch(/\/ig_1\/messages$/);
  });

  it("reads media from /me with an Instagram Login token", async () => {
    respond({ data: [] });
    await getUserMedia(IG_TOKEN, 5, "ig_1");
    expect(calledUrl().pathname).toMatch(/\/me\/media$/);
  });

  it("reads media from the account node with a Unified login token", async () => {
    respond({ data: [{ id: "media_1" }] });
    expect(await getUserMedia(FB_TOKEN, 5, "ig_1")).toEqual([{ id: "media_1" }]);
    expect(calledUrl().pathname).toMatch(/\/ig_1\/media$/);
  });

  it("refuses to guess the account for a Unified login token", async () => {
    await expect(getUserMedia(FB_TOKEN, 5)).rejects.toThrow(
      "An Instagram account ID is required"
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads the profile without user_id on graph.facebook.com and fills it from id", async () => {
    respond({ id: "ig_1", username: "brand" });
    const user = await getUserInfo(FB_TOKEN, "ig_1");
    const url = calledUrl();
    expect(url.pathname).toMatch(/\/ig_1$/);
    expect(url.searchParams.get("fields")).not.toContain("user_id");
    expect(user).toEqual({ id: "ig_1", username: "brand", user_id: "ig_1" });
  });

  it("lists the Instagram accounts assigned to the system user", async () => {
    respond({ data: [{ id: "ig_1", username: "brand" }] });
    expect(await getAssignedInstagramAccounts(FB_TOKEN)).toEqual([
      { id: "ig_1", username: "brand" },
    ]);
    expect(calledUrl().pathname).toMatch(/\/me\/assigned_instagram_accounts$/);
  });

  it("returns an empty list when business_management is missing", async () => {
    respond({ data: [] });
    expect(await getAssignedInstagramAccounts(FB_TOKEN)).toEqual([]);
  });
});
