import { Hono } from "hono";
import { apiKeyAuth } from "../../auth/middleware";
import { storeBindSession, storeGetSession } from "../../store";
import { resolveExistingWebSessionId, toWebSessionId } from "../../services/session";

const app = new Hono();

/** POST /web/bind — Bind a session to a UUID for the authenticated session owner */
app.post("/bind", apiKeyAuth, async (c) => {
  const body = await c.req.json();
  const sessionId = body.sessionId;
  // UUID can come from query param (api.js sends it in URL) or body
  const uuid = c.req.query("uuid") || body.uuid;
  const username = c.get("username");

  if (!sessionId || !uuid || !username) {
    return c.json({ error: "sessionId, uuid, and authenticated user are required" }, 400);
  }

  const resolvedSessionId = resolveExistingWebSessionId(sessionId);
  if (!resolvedSessionId) {
    return c.json({ error: "Session not found" }, 404);
  }

  const session = storeGetSession(resolvedSessionId);
  if (!session || !session.username || session.username !== username) {
    return c.json({ error: "Not allowed to bind this session" }, 403);
  }

  storeBindSession(resolvedSessionId, uuid);
  return c.json({ ok: true, sessionId: toWebSessionId(resolvedSessionId) });
});

export default app;
