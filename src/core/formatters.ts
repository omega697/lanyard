import type { SocialProviderType } from "./models.js";

/**
 * Formats a `lastSeen` timestamp into a human-readable relative time string.
 * Examples: "just now", "5m ago", "2h ago", "3d ago", "Never"
 */
export function formatLastSeen(lastSeenVal?: string | Date | number | { toDate?: () => Date } | null): string {
  if (!lastSeenVal) return "Never";
  const date =
    typeof (lastSeenVal as any)?.toDate === "function"
      ? (lastSeenVal as any).toDate()
      : new Date(lastSeenVal as string | number | Date);
  if (isNaN(date.getTime())) return "Never";

  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return "just now";

  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  return `${diffDay}d ago`;
}

/**
 * Formats an account-exists-with-different-credential error message with human-friendly provider labels.
 */
export function formatExistingAccountError(email: string, methods: string[]): string {
  const providerNames: Record<string, string> = {
    "google.com": "Google",
    "github.com": "GitHub",
    "microsoft.com": "Microsoft",
    "facebook.com": "Facebook",
    password: "Password",
    emailLink: "Email Magic Link"
  };

  const formattedMethods = methods.map((m) => providerNames[m] || m).filter(Boolean);
  const emailLabel = email.trim() ? email.trim() : "this email address";

  if (formattedMethods.length > 0) {
    const listText = formattedMethods.join(", ");
    return `An account already exists for ${emailLabel} using ${listText}. Please sign in using ${listText}, then connect this login method under My Account.`;
  }

  return `An account already exists for ${emailLabel} under a different sign-in method. Please sign in with your original method, then connect this login method under My Account.`;
}

export function getSocialProviderId(type: SocialProviderType): string {
  switch (type) {
    case "google":
      return "google.com";
    case "microsoft":
      return "microsoft.com";
    case "github":
      return "github.com";
  }
}

export function getProviderNameLabel(type: SocialProviderType): string {
  switch (type) {
    case "google":
      return "Google";
    case "microsoft":
      return "Microsoft";
    case "github":
      return "GitHub";
  }
}

/**
 * Input shape accepted by Lanyard's avatar and display-name helpers.
 */
export interface AvatarSubject {
  uid?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  displayName?: string | null;
  name?: string | null;
  email?: string | null;
  photoUrl?: string | null;
  photoURL?: string | null;
}

/**
 * Normalized avatar metadata ready for rendering an `<img>` or fallback initials badge.
 */
export interface ResolvedAvatar {
  /** Validated avatar URL, or `null` if none is available. */
  photoUrl: string | null;
  /** 1–2 uppercase Unicode-safe initials (e.g. `"AM"`, `"TM"`, `"A"`, or `"?"`). */
  initials: string;
  /** Human-readable display name (`firstName + lastName`, `displayName`, `email`, or `"User"`). */
  displayName: string;
  /** Deterministic `0..7` palette index derived from `uid || email || displayName`. */
  colorIndex: number;
}

const MAX_AVATAR_URL_LENGTH = 2048;
const MAX_RESOURCE_ID_LENGTH = 512;
const MAX_EMAIL_LENGTH = 254;
const MAX_EMAIL_LOCAL_LENGTH = 64;
const SAFE_DATA_IMAGE_REGEX = /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[a-zA-Z0-9+/=]+$/i;
const UNSAFE_URL_CHARS_REGEX = /[\u0000-\u001F\u007F\s"'<>\\]/;
const UNSAFE_ID_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\s/\\]/;
const UNSAFE_EMAIL_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F\s]/;

/**
 * Validates an email address in linear O(N) time with RFC 5321 length limits
 * and zero polynomial regex backtracking (ReDoS-safe).
 */
export function isValidEmail(email?: string | null): email is string {
  if (!email || typeof email !== "string") return false;
  const trimmed = email.trim();
  if (trimmed.length < 3 || trimmed.length > MAX_EMAIL_LENGTH) return false;
  if (UNSAFE_EMAIL_CHARS_REGEX.test(trimmed)) return false;

  const atIndex = trimmed.indexOf("@");
  if (atIndex <= 0 || atIndex > MAX_EMAIL_LOCAL_LENGTH || atIndex !== trimmed.lastIndexOf("@")) {
    return false;
  }

  const domain = trimmed.slice(atIndex + 1);
  const dotIndex = domain.indexOf(".");
  if (dotIndex <= 0 || domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    return false;
  }

  return true;
}

/**
 * Validates that a storage-agnostic resource identifier (`uid` or `scopeId`) is a non-empty
 * single path segment free of path-traversal sequences (`.`, `..`), slashes (`/`, `\`),
 * whitespace, or control characters.
 */
export function isValidResourceId(id?: string | null): id is string {
  if (!id || typeof id !== "string") return false;
  if (id.length === 0 || id.length > MAX_RESOURCE_ID_LENGTH) return false;
  if (id === "." || id === "..") return false;
  if (UNSAFE_ID_CHARS_REGEX.test(id)) return false;
  return true;
}

/**
 * Asserts that `id` is a valid, path-traversal-safe resource identifier, throwing an Error if invalid.
 */
export function assertValidResourceId(id: string | null | undefined, label = "id"): string {
  if (!isValidResourceId(id)) {
    throw new Error(`Invalid ${label}: must be a non-empty identifier without path separators or traversal segments`);
  }
  return id;
}

/**
 * Sanitizes a raw avatar URL string, stripping empty strings, `"null"`/`"undefined"` literals,
 * oversized payloads (`> 2048` chars), protocol-relative URLs (`//evil.com`), SVG data URIs
 * (`data:image/svg+xml`), and unsafe protocols or HTML-injection characters.
 */
export function sanitizeAvatarUrl(url?: string | null): string | null {
  if (!url || typeof url !== "string") return null;
  const trimmed = url.trim();
  if (!trimmed || trimmed === "null" || trimmed === "undefined") return null;
  if (trimmed.length > MAX_AVATAR_URL_LENGTH) return null;
  if (UNSAFE_URL_CHARS_REGEX.test(trimmed)) return null;

  if (trimmed.startsWith("/")) {
    // Allow single-slash relative paths ("/avatars/a.png"), reject protocol-relative ("//evil.com")
    return trimmed.startsWith("//") ? null : trimmed;
  }

  if (trimmed.toLowerCase().startsWith("data:")) {
    // Only permit raster base64 image data URIs (blocks data:image/svg+xml XSS)
    return SAFE_DATA_IMAGE_REGEX.test(trimmed) ? trimmed : null;
  }

  if (trimmed.startsWith("https://") || trimmed.startsWith("http://")) {
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol === "https:" || parsed.protocol === "http:") {
        return trimmed;
      }
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Consistently resolves the avatar URL for a target user/member record and an optional active signed-in user.
 *
 * Prioritizes the target `subject`'s own `photoUrl`. Only falls back to `activeUser.photoUrl` when
 * `subject` is omitted or represents the same `uid` as `activeUser` (preventing an admin's own avatar
 * from bleeding into another user's profile when viewing a member without a photo).
 */
export function resolveAvatarUrl(
  subject?: AvatarSubject | null,
  activeUser?: { uid?: string | null; photoUrl?: string | null; photoURL?: string | null } | null
): string | null {
  const subjectPhoto = sanitizeAvatarUrl(subject?.photoUrl ?? subject?.photoURL);
  if (subjectPhoto) return subjectPhoto;

  if (activeUser) {
    const sameUser = !subject || !subject.uid || (Boolean(activeUser.uid) && subject.uid === activeUser.uid);
    if (sameUser) {
      return sanitizeAvatarUrl(activeUser.photoUrl ?? activeUser.photoURL);
    }
  }

  return null;
}

/**
 * Resolves a human-readable display name from `firstName`/`lastName`, `displayName`/`name`, or `email`.
 */
export function formatMemberDisplayName(subject?: AvatarSubject | null, fallback = ""): string {
  if (!subject) return fallback;
  const full = [subject.firstName?.trim(), subject.lastName?.trim()].filter(Boolean).join(" ").trim();
  if (full) return full;
  const display = (subject.displayName || subject.name || "").trim();
  if (display) return display;
  const email = (subject.email || "").trim();
  if (email) return email;
  return fallback;
}

/**
 * Extracts 1–2 uppercase Unicode-safe initials from a name string or `AvatarSubject`.
 * Examples:
 * - `{ firstName: "Accenty", lastName: "McÉccent" }` -> `"AM"`
 * - `"Testy McTest"` -> `"TM"`
 * - `{ email: "alice@example.com" }` -> `"A"`
 */
export function getAvatarInitials(subjectOrName?: AvatarSubject | string | null, fallback = "?"): string {
  if (!subjectOrName) return fallback;

  let raw = "";
  if (typeof subjectOrName === "string") {
    raw = subjectOrName.trim();
  } else {
    const first = subjectOrName.firstName?.trim() || "";
    const last = subjectOrName.lastName?.trim() || "";
    if (first && last) {
      return `${Array.from(first.normalize("NFC"))[0] || ""}${Array.from(last.normalize("NFC"))[0] || ""}`.toUpperCase();
    }
    raw = formatMemberDisplayName(subjectOrName, "");
  }

  if (!raw) return fallback;

  // If the string is an email address, use the first character of the local part
  if (raw.includes("@") && !raw.includes(" ")) {
    const firstChar = Array.from(raw.normalize("NFC"))[0];
    return firstChar ? firstChar.toUpperCase() : fallback;
  }

  const words = raw
    .normalize("NFC")
    .split(/\s+/)
    .map((w) => w.replace(/^[^\p{L}\p{N}]+/gu, ""))
    .filter(Boolean);

  if (words.length === 0) return fallback;
  if (words.length === 1) {
    return (Array.from(words[0])[0] || fallback).toUpperCase();
  }

  const firstInitial = Array.from(words[0])[0] || "";
  const lastInitial = Array.from(words[words.length - 1])[0] || "";
  return `${firstInitial}${lastInitial}`.toUpperCase() || fallback;
}

/**
 * Resolves complete avatar presentation metadata (`photoUrl`, `initials`, `displayName`, and deterministic `colorIndex`)
 * for any user, member, or system admin record.
 */
export function resolveAvatar(
  subject?: AvatarSubject | null,
  activeUser?: { uid?: string | null; photoUrl?: string | null; photoURL?: string | null } | null
): ResolvedAvatar {
  const photoUrl = resolveAvatarUrl(subject, activeUser);
  const displayName = formatMemberDisplayName(subject, "User");
  const initials = getAvatarInitials(subject, "?");

  const hashSeed = (subject?.uid || subject?.email || displayName || "user").toLowerCase().trim();
  let hash = 0;
  for (let i = 0; i < hashSeed.length; i++) {
    hash = (hash * 31 + hashSeed.charCodeAt(i)) >>> 0;
  }
  const colorIndex = hash % 8;

  return {
    photoUrl,
    initials,
    displayName,
    colorIndex
  };
}
