import { EMAIL_NOT_VERIFIED_ERROR_CODE, SESSION_REVOKED_ERROR_CODE, TOKEN_STALE_ERROR_CODE } from "./models.js";

/**
 * The user's email isn't verified. Thrown by `GoogleAuthService.verifyToken` on the server (which `checkAuth` turns into
 * a 401 with `code: EMAIL_NOT_VERIFIED_ERROR_CODE`), and by the client's `authorizedFetch` when it receives that 401, so
 * apps can check `instanceof` instead of comparing strings.
 */
export class EmailNotVerifiedError extends Error {
  readonly code = EMAIL_NOT_VERIFIED_ERROR_CODE;

  constructor() {
    super("Token email must be verified");
    this.name = "EmailNotVerifiedError";
  }
}

/**
 * The user's sessions were revoked (signed out everywhere or disabled) after they signed in. Thrown by the client's
 * `authorizedFetch` after it signs the user out locally; they must sign in again.
 */
export class SessionRevokedError extends Error {
  readonly code = SESSION_REVOKED_ERROR_CODE;

  constructor() {
    super("Session has been revoked; sign in again");
    this.name = "SessionRevokedError";
  }
}

/**
 * The server still considered the user's token stale after `authorizedFetch` refreshed it and retried, which means the
 * revocation data or clocks disagree. Thrown instead of retrying indefinitely.
 */
export class TokenStaleError extends Error {
  readonly code = TOKEN_STALE_ERROR_CODE;

  constructor() {
    super("Token is still stale after refreshing it");
    this.name = "TokenStaleError";
  }
}
