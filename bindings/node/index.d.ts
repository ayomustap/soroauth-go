/**
 * Type definitions for @soroauth/node.
 *
 * Hand-written rather than generated: the binding's surface is small, and the
 * types here mirror the Go library's exported structs (EntryInfo, Finding). An
 * entry is always base64 XDR — the ABI is string based — so the type aliases
 * below say which string is which.
 */

/** A `SorobanAuthorizationEntry`, base64-encoded XDR. */
export type SignedEntryXDR = string;

/** A `HashIdPreimage`, base64-encoded XDR. */
export type PreimageXDR = string;

/** A 32-byte SHA-256 digest, lower-case hex. */
export type PayloadHex = string;

/** A 32-byte ed25519 raw seed, lower-case hex. */
export type SeedHex = string;

/** A `ScVal`, base64-encoded XDR. */
export type SignatureScValXDR = string;

/** The credential arm an entry uses (mirrors `soroauth.EntryInfo`). */
export type CredentialType =
  | "source_account"
  | "address"
  | "address_v2"
  | "address_with_delegates";

/** One node of the delegate tree. */
export interface NodeInfo {
  address: string;
  signed: boolean;
  nested?: NodeInfo[];
}

/** An entry's structure, as reported by `inspect`. */
export interface EntryInfo {
  credential_type: CredentialType;
  address_bound: boolean;
  address?: string;
  nonce?: number;
  valid_until_ledger?: number;
  top_level_signed: boolean;
  delegates?: NodeInfo[];
  root_contract?: string;
  root_function?: string;
  sub_invocations: number;
}

/** One risk finding, as reported by `analyze`. */
export interface Finding {
  code: string;
  severity: "info" | "warning" | "critical";
  title: string;
  description: string;
  rationale: string;
}

/** The base class every binding error extends; `kind` is the Go sentinel. */
export class SoroauthError extends Error {
  kind: string;
}

export class SignatureMismatch extends SoroauthError {}
export class SourceAccountCredentials extends SoroauthError {}
export class UnsupportedCredentials extends SoroauthError {}
export class NoMatchingCredentialNode extends SoroauthError {}
export class DuplicateDelegate extends SoroauthError {}
export class MissingSigner extends SoroauthError {}
export class AlreadySigned extends SoroauthError {}
export class InvalidExpiration extends SoroauthError {}
export class TooManySignatures extends SoroauthError {}
export class DecodeLimit extends SoroauthError {}

/** The typed API `load` returns. Every entry is base64 XDR. */
export interface Soroauth {
  version(): string;
  preimage(
    entry: SignedEntryXDR,
    validUntilLedger: number,
    networkPassphrase: string,
  ): { preimageXdr: PreimageXDR; payloadHex: PayloadHex };
  payload(preimageXdr: PreimageXDR): PayloadHex;
  writeSignature(
    entry: SignedEntryXDR,
    validUntilLedger: number,
    networkPassphrase: string,
    forAddress: string,
    signatureScval: SignatureScValXDR,
  ): SignedEntryXDR;
  authorizeWithSeed(
    entry: SignedEntryXDR,
    validUntilLedger: number,
    networkPassphrase: string,
    seedHex: SeedHex,
    forAddress?: string,
  ): SignedEntryXDR;
  authorizeWithSeeds(
    entry: SignedEntryXDR,
    validUntilLedger: number,
    networkPassphrase: string,
    seedsCsv: string,
    forAddress?: string,
  ): SignedEntryXDR;
  inspect(entry: SignedEntryXDR): EntryInfo;
  analyze(entry: SignedEntryXDR, currentLedger?: number): Finding[];
  renderInvocations(entry: SignedEntryXDR): string;
  renderTree(entry: SignedEntryXDR): string;
}

/** Options for `load`, for pointing at artifacts outside the package. */
export interface LoadOptions {
  addonPath?: string;
  libraryPath?: string;
}

/** Loads the native binding, or throws a `SoroauthError` naming what is missing. */
export function load(options?: LoadOptions): Soroauth;

/** The `<os>-<arch>` key a prebuild directory is named after. */
export function platformKey(): string;

/** Absolute path of the addon this module would load, or null. */
export function findAddon(): string | null;

/** Absolute path of the shared library this module would load, or null. */
export function findLibrary(): string | null;

/** The shared library's file name on this platform. */
export function nativeLibraryName(): string;
