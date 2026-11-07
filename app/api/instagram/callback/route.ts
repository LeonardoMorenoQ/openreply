import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db/client";
import { getBaseUrl, getMetaLoginMode } from "@/lib/env";
import { canConnectInstagramAccount } from "@/lib/instagram-accounts";
import {
  getAssignedInstagramAccounts,
  getLongLivedToken,
  getUserInfo,
  subscribeInstagramAccountToWebhooks,
} from "@/lib/meta/client";
import {
  encryptToken,
  exchangeCodeForToken,
  exchangeUnifiedCodeForToken,
  verifyOAuthState,
} from "@/lib/meta/oauth";
import { canManageWorkspace } from "@/lib/workspace-access";

/**
 * Store one connected account. Returns false when the Instagram account is
 * already connected to a different workspace.
 */
async function saveAccount({
  workspaceId,
  instagramId,
  accessToken,
  tokenExpiresAt,
  username,
  name,
}: {
  workspaceId: string;
  instagramId: string;
  accessToken: string;
  tokenExpiresAt: Date | null;
  username: string;
  name?: string;
}): Promise<boolean> {
  const connection = await canConnectInstagramAccount({ workspaceId, instagramId });
  if (!connection.allowed) return false;

  let webhookSubscribed = false;
  try {
    const subscription = await subscribeInstagramAccountToWebhooks(
      instagramId,
      accessToken
    );
    webhookSubscribed = Boolean(subscription.success);
  } catch (subscriptionError) {
    // Not fatal: the worker's polling reconciler still picks comments up, and
    // the app-level webhook in the Meta dashboard may deliver them anyway.
    console.warn(
      "[Instagram Callback] Webhook subscription failed:",
      subscriptionError
    );
  }

  const data = {
    username,
    name,
    accessToken: encryptToken(accessToken),
    tokenExpiresAt,
    webhookSubscribed,
  };
  const existing = await prisma.instagramAccount.findUnique({ where: { instagramId } });
  if (existing) {
    const updated = await prisma.instagramAccount.updateMany({
      where: { id: existing.id, workspaceId, provider: "META" },
      data,
    });
    return updated.count > 0;
  }
  await prisma.instagramAccount.create({
    data: { ...data, workspaceId, instagramId, provider: "META" },
  });
  return true;
}

/**
 * Unified login: the token belongs to a system user of the business, and the
 * Instagram accounts are whatever the person picked in the dialog. Connect
 * each of them. The token does not expire, so tokenExpiresAt stays null and
 * the refresh cron leaves it alone.
 */
async function connectUnified(
  code: string,
  redirectUri: string,
  workspaceId: string
): Promise<"connected" | "already_connected"> {
  const { accessToken, expiresIn } = await exchangeUnifiedCodeForToken(
    code,
    redirectUri
  );
  const assigned = await getAssignedInstagramAccounts(accessToken);
  if (assigned.length === 0) {
    throw new Error(
      "Meta returned no Instagram accounts for this login. Add business_management to the login configuration and select the Instagram account in the dialog."
    );
  }

  const tokenExpiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
  let connected = 0;
  for (const account of assigned) {
    const info = await getUserInfo(accessToken, account.id);
    const saved = await saveAccount({
      workspaceId,
      instagramId: account.id,
      accessToken,
      tokenExpiresAt,
      username: info.username,
      name: info.name,
    });
    if (saved) connected++;
  }
  return connected > 0 ? "connected" : "already_connected";
}

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const error = request.nextUrl.searchParams.get("error");
  const state = verifyOAuthState(request.nextUrl.searchParams.get("state"));
  const baseUrl = getBaseUrl();

  if (error) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=denied`);
  }

  if (!code || !state) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=invalid`);
  }

  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.redirect(`${baseUrl}/login`);
  }

  const membership = await prisma.workspaceMember.findFirst({
    where: {
      workspaceId: state.workspaceId,
      userId: session.user.id,
    },
  });

  if (!membership || !canManageWorkspace(membership.role)) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=forbidden`);
  }

  try {
    const redirectUri = `${baseUrl}/api/instagram/callback`;

    if (getMetaLoginMode() === "unified") {
      const result = await connectUnified(code, redirectUri, state.workspaceId);
      return NextResponse.redirect(
        result === "connected"
          ? `${baseUrl}/dashboard?connected=true`
          : `${baseUrl}/settings?instagram=already_connected`
      );
    }

    const { accessToken: shortLivedToken } = await exchangeCodeForToken(
      code,
      redirectUri
    );
    const { accessToken: longLivedToken, expiresIn } =
      await getLongLivedToken(shortLivedToken);
    const userInfo = await getUserInfo(longLivedToken);
    // Webhooks and the messaging API key off the professional account ID
    // (user_id), not the app-scoped `id`. Store user_id so comment webhooks
    // can be matched back to this account. Fall back to id if user_id is
    // ever absent.
    const instagramId = userInfo.user_id ?? userInfo.id;
    const saved = await saveAccount({
      workspaceId: state.workspaceId,
      instagramId,
      accessToken: longLivedToken,
      tokenExpiresAt: new Date(Date.now() + expiresIn * 1000),
      username: userInfo.username,
      name: userInfo.name,
    });

    return NextResponse.redirect(
      saved
        ? `${baseUrl}/dashboard?connected=true`
        : `${baseUrl}/settings?instagram=already_connected`
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[Instagram Callback] Error:", err);
    // The message is the only diagnostic a self-hoster gets for a failed
    // connect, so persist it alongside the other operational events rather
    // than leaving it in server logs they may not be able to reach.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "ERROR",
          workspaceId: state.workspaceId,
          message: "Instagram connection failed",
          payload: { reason: message },
        },
      })
      .catch(() => {});

    return NextResponse.redirect(
      `${baseUrl}/settings?instagram=failed&reason=${encodeURIComponent(
        message.slice(0, 200)
      )}`
    );
  }
}
