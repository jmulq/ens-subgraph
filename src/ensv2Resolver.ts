// ENSv2-specific resolver events. PermissionedResolver's
// standard ENSIP events (AddrChanged, TextChanged, etc.) need no wiring
// here — see Phase 1's Decision 4 in ensv2Discovery.ts/subgraph.yaml: the
// existing addressless "Resolver" data source already picks them up
// (addressless sources match by event topic0 network-wide, not by contract
// address/ABI). An earlier plan draft also described a resolver.ts refactor
// to "share logic" with a second wiring of those same standard events —
// that's moot given the above (there is no second wiring for it to share
// with), so resolver.ts is untouched this phase.
//
// None of the handlers below ever call ensv2Domain.ts::projectPathToDomain
// or construct Domain rows — true by construction, not by a guard: alias
// and resource records are ENSv2-only surfaces, never a substitute for a
// real registry path (an explicit non-goal of this design).
import { Address, BigInt, Bytes, crypto, ethereum, log } from "@graphprotocol/graph-ts";
import { concat, ROOT_NODE, uint256ToByteArray } from "./utils";
import { decodeName } from "./nameWrapper";
import { processEACRolesChanged } from "./ensv2Roles";
import {
  ENSv2Resolver,
  ENSv2ResolverABI,
  ENSv2ResolverAddress,
  ENSv2ResolverAlias,
  ENSv2ResolverData,
  ENSv2ResolverInterface,
  ENSv2ResolverLink,
  ENSv2ResolverRecord,
  ENSv2ResolverRecordData,
  ENSv2ResolverResource,
  ENSv2ResolverText,
} from "./types/schema";
import {
  ABIUpdated,
  AddressUpdated,
  AliasChanged,
  ContenthashUpdated,
  DataChanged,
  DataUpdated,
  EACRolesChanged,
  InterfaceUpdated,
  Linked,
  NameUpdated,
  NamedAddrResource,
  NamedDataResource,
  NamedResource,
  NamedTextResource,
  ResolverCreated,
  TextUpdated,
} from "./types/PermissionedResolver/PermissionedResolver";

// decodeName only recovers the first label + a dotted human-readable string
// (nameWrapper.ts was never built to compute a namehash). AliasChanged/
// NamedResource/etc. only ever carry a DNS-wire-format name, never a bare
// node bytes32 the way registry events do — so this parses every label
// (mirrors decodeName's own length-prefix walk) and folds them root-to-leaf
// via the same keccak256(concat(node, labelHash)) step used everywhere else
// in this codebase (ensRegistry.ts::makeSubnode, ensv2Utils.ts::pathNamehash)
// — DNS-wire order is leaf-first, namehash folding is root-first, so the
// parsed labels are walked in reverse.
export function namehashFromDnsEncoded(buf: Bytes): Bytes {
  let labels = new Array<Bytes>();
  let offset = 0;
  let hex = buf.toHexString();

  // GitHub #60: buf[offset++] traps (crashes indexing) if offset ever runs
  // past buf.length — guard the loop condition itself rather than reading
  // unconditionally, so an empty buffer or one missing its trailing
  // zero-length terminator ends the loop instead of indexing out of bounds.
  while (offset < buf.length) {
    let len = buf[offset++];
    if (len == 0) {
      break;
    }
    // A label claiming more content bytes than actually remain — truncated
    // or malformed input. Stop folding here (whatever labels were already
    // parsed still get used) rather than slicing/reading past the buffer.
    if (offset + len > buf.length) {
      log.warning(
        "namehashFromDnsEncoded: truncated/malformed DNS-wire name — label length {} at offset {} exceeds buffer length {}; folding only the labels parsed so far",
        [len.toString(), (offset - 1).toString(), buf.length.toString()]
      );
      break;
    }
    let labelHex = hex.slice((offset + 1) * 2, (offset + 1 + len) * 2);
    labels.push(Bytes.fromHexString(labelHex));
    offset += len;
  }

  let node: Bytes = ROOT_NODE;
  for (let i = labels.length - 1; i >= 0; i--) {
    let labelHash = Bytes.fromByteArray(crypto.keccak256(labels[i]));
    node = Bytes.fromByteArray(crypto.keccak256(concat(node, labelHash)));
  }
  return node;
}

// Exported so ensv2Paths.ts::handleResolverUpdated can share this
// implementation instead of maintaining its own copy (audit finding 23).
export function getOrCreateResolver(address: Address): ENSv2Resolver {
  let id: Bytes = address;
  let resolver = ENSv2Resolver.load(id);
  if (resolver == null) {
    resolver = new ENSv2Resolver(id);
    resolver.address = address;
    resolver.save();
  }
  return resolver;
}

function decodedNameOf(buf: Bytes): string | null {
  let decoded = decodeName(buf);
  if (decoded == null) {
    return null;
  }
  return decoded[1];
}

export function handleAliasChanged(event: AliasChanged): void {
  let resolver = getOrCreateResolver(event.address);
  // fromName is DNS-wire-encoded, arbitrary length — not safe to
  // concatenate raw (fix plan Phase 5 Decision 1/2). Use its namehash
  // instead (already computed below as fromNode, a fixed 32-byte hash) —
  // more meaningful as an id component than the raw bytes anyway.
  let fromNode = namehashFromDnsEncoded(event.params.fromName);
  let id = Bytes.fromByteArray(concat(resolver.id, fromNode));

  let alias = ENSv2ResolverAlias.load(id);
  if (alias == null) {
    alias = new ENSv2ResolverAlias(id);
    alias.resolver = resolver.id;
  }
  alias.fromName = event.params.fromName;
  alias.fromNode = fromNode;
  alias.fromNameDecoded = decodedNameOf(event.params.fromName);

  // Empty toName is the clearing signal — not explicit in the proposal, but
  // consistent with the address(0)-clears convention used everywhere else.
  let hasTarget = event.params.toName.length > 0;
  if (hasTarget) {
    alias.toName = event.params.toName;
    alias.toNode = namehashFromDnsEncoded(event.params.toName);
    alias.toNameDecoded = decodedNameOf(event.params.toName);
  } else {
    alias.toName = null;
    alias.toNode = null;
    alias.toNameDecoded = null;
  }
  alias.active = hasTarget;
  alias.blockNumber = event.block.number;
  alias.transactionID = event.transaction.hash;
  alias.logIndex = event.logIndex;
  alias.save();
}

// idSuffix is a fixed-width Bytes tag distinguishing kind + any extra key
// material (fix plan Phase 5 Decision 1) — see each caller below for how
// it's built. Concatenated after a 32-byte resource, no delimiter needed:
// NAME's suffix (4 bytes) can never collide with TEXT/DATA/ADDR's (36
// bytes, and each starts with its own distinct 4-byte kind tag).
function saveNamedResource(
  resolver: ENSv2Resolver,
  idSuffix: Bytes,
  resource: BigInt,
  name: Bytes,
  kind: string,
  key: string | null,
  keyHash: Bytes | null,
  coinType: BigInt | null,
  event: ethereum.Event
): void {
  let id = Bytes.fromByteArray(
    concat(concat(resolver.id, uint256ToByteArray(resource)), idSuffix)
  );
  let entity = ENSv2ResolverResource.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverResource(id);
    entity.resolver = resolver.id;
    entity.resource = resource;
  }
  entity.node = namehashFromDnsEncoded(name);
  entity.name = name;
  entity.nameDecoded = decodedNameOf(name);
  entity.kind = kind;
  if (key !== null) {
    entity.key = key as string;
  }
  if (keyHash !== null) {
    entity.keyHash = keyHash as Bytes;
  }
  if (coinType !== null) {
    entity.coinType = coinType as BigInt;
  }
  entity.active = true;
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}

export function handleNamedResource(event: NamedResource): void {
  let resolver = getOrCreateResolver(event.address);
  saveNamedResource(
    resolver,
    Bytes.fromUTF8("NAME"),
    event.params.resource,
    event.params.name,
    "NAME",
    null,
    null,
    null,
    event
  );
}

// NamedTextResource/NamedDataResource share an identical event shape
// (resource, name, keyHash, key) — one internal helper, thin wrapper
// exports. AssemblyScript has no union
// types, so the helper takes primitives rather than either event class.
function handleNamedKeyedResource(
  resolverAddress: Address,
  resource: BigInt,
  name: Bytes,
  keyHash: Bytes,
  key: string,
  kind: string,
  event: ethereum.Event
): void {
  let resolver = getOrCreateResolver(resolverAddress);
  // kind is always exactly 4 ASCII chars ("TEXT"/"DATA"), keyHash always 32
  // bytes — fixed-width, no delimiter needed.
  let idSuffix = Bytes.fromByteArray(concat(Bytes.fromUTF8(kind), keyHash));
  saveNamedResource(
    resolver,
    idSuffix,
    resource,
    name,
    kind,
    key,
    keyHash,
    null,
    event
  );
}

export function handleNamedTextResource(event: NamedTextResource): void {
  handleNamedKeyedResource(
    event.address,
    event.params.resource,
    event.params.name,
    event.params.keyHash,
    event.params.key,
    "TEXT",
    event
  );
}

export function handleNamedDataResource(event: NamedDataResource): void {
  handleNamedKeyedResource(
    event.address,
    event.params.resource,
    event.params.name,
    event.params.keyHash,
    event.params.key,
    "DATA",
    event
  );
}

export function handleNamedAddrResource(event: NamedAddrResource): void {
  let resolver = getOrCreateResolver(event.address);
  // "ADDR" (4 bytes) + coinType as a 32-byte big-endian value — fixed-width.
  let idSuffix = Bytes.fromByteArray(
    concat(Bytes.fromUTF8("ADDR"), uint256ToByteArray(event.params.coinType))
  );
  saveNamedResource(
    resolver,
    idSuffix,
    event.params.resource,
    event.params.name,
    "ADDR",
    null,
    null,
    event.params.coinType,
    event
  );
}

export function handleDataChanged(event: DataChanged): void {
  let resolver = getOrCreateResolver(event.address);
  // key is arbitrary-length user-supplied text, not safe to concatenate raw
  // (fix plan Phase 5 Decision 2) — hash it first, same as its sibling
  // TEXT/DATA resource ids already do via the ABI's own keyHash param.
  let keyHash = Bytes.fromByteArray(crypto.keccak256(Bytes.fromUTF8(event.params.key)));
  let id = Bytes.fromByteArray(
    concat(concat(resolver.id, event.params.node), keyHash)
  );

  let data = ENSv2ResolverData.load(id);
  if (data == null) {
    data = new ENSv2ResolverData(id);
    data.resolver = resolver.id;
    data.node = event.params.node;
    data.key = event.params.key;
  }
  // ENSv2ResolverData has no `value` field: the real signature is
  // DataChanged(bytes32 indexed node, string indexed indexedKey, string key,
  // bytes indexed indexedData) — the actual data bytes are only logged as
  // an indexed parameter (indexedData), so only its keccak256 hash reaches
  // the log, never the raw bytes. A hard ABI constraint, not an
  // implementation gap — nothing here could ever populate one.
  data.blockNumber = event.block.number;
  data.transactionID = event.transaction.hash;
  data.logIndex = event.logIndex;
  data.save();
}

export function handleEACRolesChanged(event: EACRolesChanged): void {
  processEACRolesChanged(
    event.address,
    event.params.resource,
    event.params.account,
    event.params.oldRoleBitmap,
    event.params.newRoleBitmap,
    event.block,
    event.transaction.hash,
    event.logIndex
  );
}

// --- New (recordId-keyed) PermissionedResolver event model (GitHub #43) ---
// See schema.graphql's own comment above ENSv2ResolverRecord for what a
// recordId actually is. Wired alongside the old handlers above rather than
// replacing them — the actually-deployed Sepolia implementation still
// emits the old event set, and this is an addressless data source, so both
// models route correctly with zero topic0 collision risk.

// Caller must never invoke with recordId.isZero() — 0 is the "no record"
// sentinel (see handleLinked), not a real record to get-or-create.
function getOrCreateRecord(
  resolver: ENSv2Resolver,
  recordId: BigInt,
  event: ethereum.Event
): ENSv2ResolverRecord {
  let id = Bytes.fromByteArray(concat(resolver.id, uint256ToByteArray(recordId)));
  let record = ENSv2ResolverRecord.load(id);
  if (record == null) {
    record = new ENSv2ResolverRecord(id);
    record.resolver = resolver.id;
    record.recordId = recordId;
    record.createdAtBlock = event.block.number;
  }
  record.updatedAtBlock = event.block.number;
  record.save();
  return record;
}

// Also fires from the bare implementation contract's own constructor, not
// just a proxy's initialize() — creates a harmless stray ENSv2Resolver row
// for the implementation address itself, which never gets any records or
// links attached.
export function handleResolverCreated(event: ResolverCreated): void {
  getOrCreateResolver(event.address);
}

export function handleLinked(event: Linked): void {
  let resolver = getOrCreateResolver(event.address);
  let recordId = event.params.recordId;
  let id = Bytes.fromByteArray(concat(resolver.id, event.params.node));

  let link = ENSv2ResolverLink.load(id);
  if (link == null) {
    link = new ENSv2ResolverLink(id);
    link.resolver = resolver.id;
    link.node = event.params.node;
  }
  link.name = event.params.name;
  link.nameDecoded = decodedNameOf(event.params.name);
  link.recordId = recordId;
  // recordId 0 is the explicit-unlink sentinel (linkToRecord(name, 0)) —
  // not a real record, so no getOrCreateRecord call and no relation.
  if (recordId.isZero()) {
    link.record = null;
    link.active = false;
  } else {
    let record = getOrCreateRecord(resolver, recordId, event);
    link.record = record.id;
    link.active = true;
  }
  link.blockNumber = event.block.number;
  link.transactionID = event.transaction.hash;
  link.logIndex = event.logIndex;
  link.save();
}

export function handleContenthashUpdated(event: ContenthashUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  record.contenthash = event.params.hash;
  record.save();
}

export function handleNameUpdated(event: NameUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  record.primaryName = event.params.primaryName;
  record.save();
}

export function handleAddressUpdated(event: AddressUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  let id = Bytes.fromByteArray(
    concat(record.id, uint256ToByteArray(event.params.coinType))
  );
  let entity = ENSv2ResolverAddress.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverAddress(id);
    entity.record = record.id;
    entity.coinType = event.params.coinType;
  }
  entity.addressBytes = event.params.addressBytes;
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}

export function handleTextUpdated(event: TextUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  let id = Bytes.fromByteArray(concat(record.id, event.params.keyHash));
  let entity = ENSv2ResolverText.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverText(id);
    entity.record = record.id;
    entity.keyHash = event.params.keyHash;
  }
  entity.key = event.params.key;
  entity.value = event.params.value;
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}

// Named handleRecordDataUpdated, not handleDataUpdated, so it doesn't read
// as a collision with the existing (old-model) handleDataChanged above.
export function handleRecordDataUpdated(event: DataUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  let id = Bytes.fromByteArray(concat(record.id, event.params.keyHash));
  let entity = ENSv2ResolverRecordData.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverRecordData(id);
    entity.record = record.id;
    entity.keyHash = event.params.keyHash;
  }
  entity.key = event.params.key;
  entity.value = event.params.value;
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}

export function handleABIUpdated(event: ABIUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  let id = Bytes.fromByteArray(
    concat(record.id, uint256ToByteArray(event.params.contentType))
  );
  let entity = ENSv2ResolverABI.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverABI(id);
    entity.record = record.id;
    entity.contentType = event.params.contentType;
  }
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}

export function handleInterfaceUpdated(event: InterfaceUpdated): void {
  let resolver = getOrCreateResolver(event.address);
  let record = getOrCreateRecord(resolver, event.params.recordId, event);
  let id = Bytes.fromByteArray(concat(record.id, event.params.interfaceId));
  let entity = ENSv2ResolverInterface.load(id);
  if (entity == null) {
    entity = new ENSv2ResolverInterface(id);
    entity.record = record.id;
    entity.interfaceId = event.params.interfaceId;
  }
  entity.implementer = event.params.implementer;
  entity.blockNumber = event.block.number;
  entity.transactionID = event.transaction.hash;
  entity.logIndex = event.logIndex;
  entity.save();
}
