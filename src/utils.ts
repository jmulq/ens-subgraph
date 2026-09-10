// Import types and APIs from graph-ts
import { BigInt, ByteArray, Bytes, ethereum, log } from "@graphprotocol/graph-ts";
import { Account, Domain } from "./types/schema";

// Fixed-width Bytes concatenation, no delimiter needed: block.number and
// logIndex are each encoded as a 32-byte big-endian value via
// uint256ToByteArray, so there's no ambiguity despite no separator
// (fix plan Phase 5 Decision 1).
export function createEventID(event: ethereum.Event): Bytes {
  return Bytes.fromByteArray(
    concat(
      uint256ToByteArray(event.block.number),
      uint256ToByteArray(event.logIndex)
    )
  );
}

// String-id counterpart to createEventID, restored for the legacy
// ENSv1-consumer-facing event entities alongside the id revert (issue #8) —
// ENSv2-native event entities keep using createEventID (Bytes) above.
export function createLegacyEventID(event: ethereum.Event): string {
  return event.block.number
    .toString()
    .concat("-")
    .concat(event.logIndex.toString());
}

// Bytes-typed: still used for raw Bytes32/keccak256 operations (ethRegistrar.ts's
// rootNode, ensv2Domain.ts/ensv2Discovery.ts's ENSv2 baseNamehash comparisons),
// which never stopped being Bytes-typed even where the legacy entity ids
// referencing them (Domain.id etc.) reverted to String (issue #8).
export const ETH_NODE = Bytes.fromHexString(
  "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
);
export const ROOT_NODE = Bytes.fromHexString(
  "0x0000000000000000000000000000000000000000000000000000000000000000"
);
// Two distinct EMPTY_ADDRESS constants, restored alongside the legacy id
// revert (issue #8): EMPTY_ADDRESS (string) compares against legacy
// String-typed relation fields (Domain.owner, NewResolver.resolver, ...);
// EMPTY_ADDRESS_BYTEARRAY compares against raw Bytes/Address event params.
export const EMPTY_ADDRESS = "0x0000000000000000000000000000000000000000";
export const EMPTY_ADDRESS_BYTEARRAY = new ByteArray(20);

// Helper for concatenating two byte arrays
export function concat(a: ByteArray, b: ByteArray): ByteArray {
  let out = new Uint8Array(a.length + b.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i];
  }
  for (let j = 0; j < b.length; j++) {
    out[a.length + j] = b[j];
  }
  // return out as ByteArray
  return changetype<ByteArray>(out);
}

export function byteArrayFromHex(s: string): ByteArray {
  if (s.length % 2 !== 0) {
    throw new TypeError("Hex string must have an even number of characters");
  }
  let out = new Uint8Array(s.length / 2);
  for (var i = 0; i < s.length; i += 2) {
    out[i / 2] = parseInt(s.substring(i, i + 2), 16) as u32;
  }
  return changetype<ByteArray>(out);
}

export function uint256ToByteArray(i: BigInt): ByteArray {
  let hex = i.toHex().slice(2).padStart(64, "0");
  return byteArrayFromHex(hex);
}

// 4-byte big-endian encoding for small loop/index counters (fix plan Phase 5
// Decision 1) — the i32 equivalent of uint256ToByteArray, for composite ids
// that embed a batch-transfer loop index or a path/namespace index counter
// rather than a full BigInt.
export function i32ToBytes(i: i32): ByteArray {
  let out = new Uint8Array(4);
  out[0] = ((i >> 24) & 0xff) as u8;
  out[1] = ((i >> 16) & 0xff) as u8;
  out[2] = ((i >> 8) & 0xff) as u8;
  out[3] = (i & 0xff) as u8;
  return changetype<ByteArray>(out);
}

// Takes a Bytes address (every caller already has one — either a raw
// Address event param or an ENSv2 entity field) so the many ENSv2-side call
// sites didn't need touching when Account.id reverted to String (issue #8);
// the hex-string conversion happens once, here.
export function createOrLoadAccount(address: Bytes): Account {
  let id = address.toHexString();
  let account = Account.load(id);
  if (account == null) {
    account = new Account(id);
    account.save();
  }

  return account;
}

export function createOrLoadDomain(node: Bytes): Domain {
  let id = node.toHexString();
  let domain = Domain.load(id);
  if (domain == null) {
    domain = new Domain(id);
    domain.save();
  }

  return domain;
}

export function checkValidLabel(name: string | null): boolean {
  if (name == null) {
    return false;
  }
  // for compiler
  name = name!;
  for (let i = 0; i < name.length; i++) {
    let charCode = name.charCodeAt(i);
    if (charCode === 0) {
      // 0 = null byte
      log.warning("Invalid label '{}' contained null byte. Skipping.", [name]);
      return false;
    } else if (charCode === 46) {
      // 46 = .
      log.warning(
        "Invalid label '{}' contained separator char '.'. Skipping.",
        [name]
      );
      return false;
    } else if (charCode === 91) {
      // 91 = [
      log.warning("Invalid label '{}' contained char '['. Skipping.", [name]);
      return false;
    } else if (charCode === 93) {
      // 93 = ]
      log.warning("Invalid label '{}' contained char ']'. Skipping.", [name]);
      return false;
    }
  }

  return true;
}
