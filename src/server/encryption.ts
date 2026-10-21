import crypto from "node:crypto";
import type { EncryptedSecretData, SecretCipher } from "../core/index.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function isEncryptedSecretData(value: unknown): value is EncryptedSecretData {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.ciphertext === "string" &&
    typeof candidate.iv === "string" &&
    typeof candidate.tag === "string" &&
    candidate.iv.length > 0 &&
    candidate.tag.length > 0
  );
}

/**
 * Creates an AES-256-GCM `SecretCipher` from a master key string (deriving a 32-byte key via SHA-256).
 * Format-compatible with `{ ciphertext, iv, tag }` hex envelopes in Firestore.
 */
export function createSecretCipher(masterKey: string): SecretCipher {
  if (!masterKey || typeof masterKey !== "string" || !masterKey.trim()) {
    throw new Error("A non-empty master encryption key is required to create a SecretCipher.");
  }
  const keyBuffer = crypto.createHash("sha256").update(masterKey).digest();

  return {
    encrypt(plaintext: string): EncryptedSecretData {
      const iv = crypto.randomBytes(IV_LENGTH);
      const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);
      let ciphertext = cipher.update(plaintext, "utf8", "hex");
      ciphertext += cipher.final("hex");
      const tag = cipher.getAuthTag().toString("hex");
      return {
        ciphertext,
        iv: iv.toString("hex"),
        tag
      };
    },
    decrypt(encrypted: EncryptedSecretData): string {
      if (!isEncryptedSecretData(encrypted)) {
        throw new Error("Invalid encrypted secret payload");
      }
      const ivBuffer = Buffer.from(encrypted.iv, "hex");
      const tagBuffer = Buffer.from(encrypted.tag, "hex");
      const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, ivBuffer);
      decipher.setAuthTag(tagBuffer);
      let decrypted = decipher.update(encrypted.ciphertext, "hex", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    }
  };
}

/**
 * Convenience helper to encrypt a single secret string with AES-256-GCM.
 */
export function encryptSecret(
  plaintext: string,
  masterKey = process.env.MASTER_ENCRYPTION_KEY || ""
): EncryptedSecretData {
  return createSecretCipher(masterKey).encrypt(plaintext);
}

/**
 * Convenience helper to decrypt a single AES-256-GCM `{ ciphertext, iv, tag }` payload.
 */
export function decryptSecret(
  encrypted: EncryptedSecretData,
  masterKey = process.env.MASTER_ENCRYPTION_KEY || ""
): string {
  return createSecretCipher(masterKey).decrypt(encrypted);
}
