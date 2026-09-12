import { Address, BigInt, Bytes, crypto, ethereum } from "@graphprotocol/graph-ts";
import {
  afterEach,
  assert,
  clearStore,
  newMockEvent,
  test,
} from "matchstick-as/assembly/index";
import {
  handleABIUpdated,
  handleAddressUpdated,
  handleAliasChanged,
  handleContenthashUpdated,
  handleDataChanged,
  handleInterfaceUpdated,
  handleLinked,
  handleNameUpdated,
  handleNamedAddrResource,
  handleNamedDataResource,
  handleNamedResource,
  handleNamedTextResource,
  handleRecordDataUpdated,
  handleResolverCreated,
  handleTextUpdated,
  namehashFromDnsEncoded,
} from "../src/ensv2Resolver";
import { createResolverID, handleAddrChanged } from "../src/resolver";
import {
  ABIUpdated,
  AddressUpdated,
  AliasChanged,
  ContenthashUpdated,
  DataChanged,
  DataUpdated,
  InterfaceUpdated,
  Linked,
  NameUpdated,
  NamedAddrResource,
  NamedDataResource,
  NamedResource,
  NamedTextResource,
  ResolverCreated,
  TextUpdated,
} from "../src/types/PermissionedResolver/PermissionedResolver";
import { AddrChanged } from "../src/types/Resolver/Resolver";
import {
  ENSv2Resolver,
  ENSv2ResolverData,
  ENSv2ResolverRecord,
  Resolver,
} from "../src/types/schema";

const PERMISSIONED_RESOLVER = "0x11111111111111111111111111111111111111aa";

// DNS-wire-format encode a single-label name, e.g. "alice" ->
// 0x05616c696365 00 (length-prefixed label + zero-length root terminator).
function encodeLabel(label: string): Bytes {
  let labelBytes = Bytes.fromUTF8(label);
  let out = new Uint8Array(labelBytes.length + 2);
  out[0] = labelBytes.length as u8;
  for (let i = 0; i < labelBytes.length; i++) {
    out[i + 1] = labelBytes[i];
  }
  out[labelBytes.length + 1] = 0;
  return Bytes.fromUint8Array(out);
}

const createAliasChangedEvent = (
  fromName: Bytes,
  toName: Bytes
): AliasChanged => {
  let mockEvent = newMockEvent();
  let event = new AliasChanged(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "indexedFromName",
      ethereum.Value.fromBytes(Bytes.fromByteArray(crypto.keccak256(fromName)))
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "indexedToName",
      ethereum.Value.fromBytes(Bytes.fromByteArray(crypto.keccak256(toName)))
    )
  );
  event.parameters.push(
    new ethereum.EventParam("fromName", ethereum.Value.fromBytes(fromName))
  );
  event.parameters.push(
    new ethereum.EventParam("toName", ethereum.Value.fromBytes(toName))
  );
  return event;
};

const createNamedResourceEvent = (
  resource: BigInt,
  name: Bytes
): NamedResource => {
  let mockEvent = newMockEvent();
  let event = new NamedResource(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "resource",
      ethereum.Value.fromUnsignedBigInt(resource)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("name", ethereum.Value.fromBytes(name))
  );
  return event;
};

const createNamedTextResourceEvent = (
  resource: BigInt,
  name: Bytes,
  keyHash: Bytes,
  key: string
): NamedTextResource => {
  let mockEvent = newMockEvent();
  let event = new NamedTextResource(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "resource",
      ethereum.Value.fromUnsignedBigInt(resource)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("name", ethereum.Value.fromBytes(name))
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(keyHash))
  );
  event.parameters.push(
    new ethereum.EventParam("key", ethereum.Value.fromString(key))
  );
  return event;
};

const createNamedDataResourceEvent = (
  resource: BigInt,
  name: Bytes,
  keyHash: Bytes,
  key: string
): NamedDataResource => {
  let mockEvent = newMockEvent();
  let event = new NamedDataResource(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "resource",
      ethereum.Value.fromUnsignedBigInt(resource)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("name", ethereum.Value.fromBytes(name))
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(keyHash))
  );
  event.parameters.push(
    new ethereum.EventParam("key", ethereum.Value.fromString(key))
  );
  return event;
};

const createNamedAddrResourceEvent = (
  resource: BigInt,
  name: Bytes,
  coinType: BigInt
): NamedAddrResource => {
  let mockEvent = newMockEvent();
  let event = new NamedAddrResource(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "resource",
      ethereum.Value.fromUnsignedBigInt(resource)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("name", ethereum.Value.fromBytes(name))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "coinType",
      ethereum.Value.fromUnsignedBigInt(coinType)
    )
  );
  return event;
};

const createDataChangedEvent = (
  node: Bytes,
  key: string
): DataChanged => {
  let mockEvent = newMockEvent();
  let event = new DataChanged(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("node", ethereum.Value.fromFixedBytes(node))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "indexedKey",
      ethereum.Value.fromBytes(Bytes.fromUTF8(key))
    )
  );
  event.parameters.push(
    new ethereum.EventParam("key", ethereum.Value.fromString(key))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "indexedData",
      ethereum.Value.fromBytes(Bytes.fromUTF8("somevalue"))
    )
  );
  return event;
};

// --- New (recordId-keyed) event model mock-event builders ---

const createResolverCreatedEvent = (): ResolverCreated => {
  let mockEvent = newMockEvent();
  let event = new ResolverCreated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  return event;
};

const createLinkedEvent = (
  recordId: BigInt,
  node: Bytes,
  name: Bytes
): Linked => {
  let mockEvent = newMockEvent();
  let event = new Linked(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("node", ethereum.Value.fromFixedBytes(node))
  );
  event.parameters.push(
    new ethereum.EventParam("name", ethereum.Value.fromBytes(name))
  );
  return event;
};

const createContenthashUpdatedEvent = (
  recordId: BigInt,
  hash: Bytes
): ContenthashUpdated => {
  let mockEvent = newMockEvent();
  let event = new ContenthashUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("hash", ethereum.Value.fromBytes(hash))
  );
  return event;
};

const createNameUpdatedEvent = (
  recordId: BigInt,
  primaryName: string
): NameUpdated => {
  let mockEvent = newMockEvent();
  let event = new NameUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "primaryName",
      ethereum.Value.fromString(primaryName)
    )
  );
  return event;
};

const createAddressUpdatedEvent = (
  recordId: BigInt,
  coinType: BigInt,
  addressBytes: Bytes
): AddressUpdated => {
  let mockEvent = newMockEvent();
  let event = new AddressUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "coinType",
      ethereum.Value.fromUnsignedBigInt(coinType)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "addressBytes",
      ethereum.Value.fromBytes(addressBytes)
    )
  );
  return event;
};

const createTextUpdatedEvent = (
  recordId: BigInt,
  keyHash: Bytes,
  key: string,
  value: string
): TextUpdated => {
  let mockEvent = newMockEvent();
  let event = new TextUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(keyHash))
  );
  event.parameters.push(
    new ethereum.EventParam("key", ethereum.Value.fromString(key))
  );
  event.parameters.push(
    new ethereum.EventParam("value", ethereum.Value.fromString(value))
  );
  return event;
};

const createDataUpdatedEvent = (
  recordId: BigInt,
  keyHash: Bytes,
  key: string,
  value: Bytes
): DataUpdated => {
  let mockEvent = newMockEvent();
  let event = new DataUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(keyHash))
  );
  event.parameters.push(
    new ethereum.EventParam("key", ethereum.Value.fromString(key))
  );
  event.parameters.push(
    new ethereum.EventParam("value", ethereum.Value.fromBytes(value))
  );
  return event;
};

const createABIUpdatedEvent = (
  recordId: BigInt,
  contentType: BigInt
): ABIUpdated => {
  let mockEvent = newMockEvent();
  let event = new ABIUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "contentType",
      ethereum.Value.fromUnsignedBigInt(contentType)
    )
  );
  return event;
};

const createInterfaceUpdatedEvent = (
  recordId: BigInt,
  interfaceId: Bytes,
  implementer: Address
): InterfaceUpdated => {
  let mockEvent = newMockEvent();
  let event = new InterfaceUpdated(
    Address.fromString(PERMISSIONED_RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam(
      "recordId",
      ethereum.Value.fromUnsignedBigInt(recordId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "interfaceId",
      ethereum.Value.fromFixedBytes(interfaceId)
    )
  );
  event.parameters.push(
    new ethereum.EventParam(
      "implementer",
      ethereum.Value.fromAddress(implementer)
    )
  );
  return event;
};

afterEach(() => {
  clearStore();
});

// assert.fieldEquals compares an entity's id as its lowercase-hex string
// form regardless of the underlying GraphQL type (fix plan Phase 5).
// Production code now builds these ids as fixed-width Bytes concatenation
// with no delimiter (a BigInt component is a 32-byte big-endian value,
// src/utils.ts::uint256ToByteArray) — these mirror that exact encoding, and
// hexOf mirrors Bytes.fromUTF8(kindTag).toHexString() for the fixed 4-byte
// "NAME"/"TEXT"/"DATA"/"ADDR" kind tags.
function bigIntHex32(i: BigInt): string {
  return i.toHex().slice(2).padStart(64, "0");
}
function hexOf(b: Bytes): string {
  return b.toHexString().slice(2);
}

test("AliasChanged set produces ENSv2ResolverAlias, clearing (empty toName) deactivates without deleting", () => {
  let fromName = encodeLabel("alice");
  let toName = encodeLabel("bob");
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let id = resolverId.concat(hexOf(namehashFromDnsEncoded(fromName)));

  handleAliasChanged(createAliasChangedEvent(fromName, toName));

  assert.fieldEquals("ENSv2ResolverAlias", id, "active", "true");
  assert.fieldEquals("ENSv2ResolverAlias", id, "fromNameDecoded", "alice");
  assert.fieldEquals("ENSv2ResolverAlias", id, "toNameDecoded", "bob");

  handleAliasChanged(createAliasChangedEvent(fromName, Bytes.fromUint8Array(new Uint8Array(0))));

  assert.fieldEquals("ENSv2ResolverAlias", id, "active", "false");
  // Row still exists, not deleted.
  assert.fieldEquals("ENSv2ResolverAlias", id, "fromNameDecoded", "alice");
});

test("NamedResource produces ENSv2ResolverResource with kind NAME", () => {
  let resource = BigInt.fromI32(1);
  let name = encodeLabel("carol");
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let id = resolverId.concat(bigIntHex32(resource)).concat(hexOf(Bytes.fromUTF8("NAME")));

  handleNamedResource(createNamedResourceEvent(resource, name));

  assert.fieldEquals("ENSv2ResolverResource", id, "kind", "NAME");
  assert.fieldEquals("ENSv2ResolverResource", id, "nameDecoded", "carol");
});

test("NamedTextResource and NamedDataResource on the same resource with different keyHashes produce two distinct rows", () => {
  let resource = BigInt.fromI32(2);
  let name = encodeLabel("dave");
  let textKeyHash = Bytes.fromI32(1);
  let dataKeyHash = Bytes.fromI32(2);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let textId = resolverId
    .concat(bigIntHex32(resource))
    .concat(hexOf(Bytes.fromUTF8("TEXT")))
    .concat(hexOf(textKeyHash));
  let dataId = resolverId
    .concat(bigIntHex32(resource))
    .concat(hexOf(Bytes.fromUTF8("DATA")))
    .concat(hexOf(dataKeyHash));

  handleNamedTextResource(
    createNamedTextResourceEvent(resource, name, textKeyHash, "avatar")
  );
  handleNamedDataResource(
    createNamedDataResourceEvent(resource, name, dataKeyHash, "pubkey")
  );

  assert.fieldEquals("ENSv2ResolverResource", textId, "kind", "TEXT");
  assert.fieldEquals("ENSv2ResolverResource", textId, "key", "avatar");
  assert.fieldEquals("ENSv2ResolverResource", dataId, "kind", "DATA");
  assert.fieldEquals("ENSv2ResolverResource", dataId, "key", "pubkey");
});

test("NamedAddrResource for two coinTypes on the same resource produces two distinct rows", () => {
  let resource = BigInt.fromI32(3);
  let name = encodeLabel("erin");
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let ethCoinType = BigInt.fromI32(60);
  let btcCoinType = BigInt.fromI32(0);
  let ethId = resolverId
    .concat(bigIntHex32(resource))
    .concat(hexOf(Bytes.fromUTF8("ADDR")))
    .concat(bigIntHex32(ethCoinType));
  let btcId = resolverId
    .concat(bigIntHex32(resource))
    .concat(hexOf(Bytes.fromUTF8("ADDR")))
    .concat(bigIntHex32(btcCoinType));

  handleNamedAddrResource(
    createNamedAddrResourceEvent(resource, name, ethCoinType)
  );
  handleNamedAddrResource(
    createNamedAddrResourceEvent(resource, name, btcCoinType)
  );

  assert.fieldEquals("ENSv2ResolverResource", ethId, "coinType", "60");
  assert.fieldEquals("ENSv2ResolverResource", btcId, "coinType", "0");
});

test("DataChanged produces ENSv2ResolverData with node/key set", () => {
  let node = Bytes.fromI32(9);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let keyHash = Bytes.fromByteArray(crypto.keccak256(Bytes.fromUTF8("mykey")));
  let id = resolverId.concat(hexOf(node)).concat(hexOf(keyHash));

  handleDataChanged(createDataChangedEvent(node, "mykey"));

  assert.fieldEquals("ENSv2ResolverData", id, "key", "mykey");
  let entity = ENSv2ResolverData.load(Bytes.fromHexString(id));
  assert.assertTrue(entity != null);
});

test("a standard ENSIP event fired from a PermissionedResolver-style address is still processed by the existing addressless Resolver source", () => {
  let node = Bytes.fromHexString(
    "0x7857c9824139b8a8c3cb04712b41558b4878c55fa9c1e5390e910ee3220c3cce"
  );
  let permissionedResolverAddress = Address.fromString(PERMISSIONED_RESOLVER);

  let mockEvent = newMockEvent();
  let event = new AddrChanged(
    permissionedResolverAddress,
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("node", ethereum.Value.fromFixedBytes(node))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "a",
      ethereum.Value.fromAddress(
        Address.fromString("0x8e8db5ccef88cca9d624701db544989c996e3211")
      )
    )
  );

  let resolverId = createResolverID(node, permissionedResolverAddress);
  assert.assertNull(Resolver.load(resolverId));

  handleAddrChanged(event);

  assert.assertNotNull(Resolver.load(resolverId));
});

test("none of this phase's handlers ever create a Domain row", () => {
  let resource = BigInt.fromI32(4);
  let name = encodeLabel("frank");
  handleNamedResource(createNamedResourceEvent(resource, name));
  handleAliasChanged(createAliasChangedEvent(encodeLabel("grace"), encodeLabel("henry")));
  handleDataChanged(createDataChangedEvent(Bytes.fromI32(10), "somekey"));

  // No Domain entity of any kind exists in the store after any of the above.
  assert.entityCount("Domain", 0);
});

// --- New (recordId-keyed) event model (GitHub #43) ---

test("ResolverCreated creates only the ENSv2Resolver row, nothing else", () => {
  handleResolverCreated(createResolverCreatedEvent());

  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  assert.assertNotNull(ENSv2Resolver.load(Bytes.fromHexString(resolverId)));
  assert.entityCount("ENSv2ResolverRecord", 0);
  assert.entityCount("ENSv2ResolverLink", 0);
});

test("Linked with a non-zero recordId sets record/active; re-linking to a different recordId overwrites the same row; linking to recordId 0 clears record and active", () => {
  let node = Bytes.fromI32(101);
  let name = encodeLabel("ivan");
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let linkId = resolverId.concat(hexOf(node));
  let recordId1 = BigInt.fromI32(1);
  let recordId2 = BigInt.fromI32(2);
  let record1Id = resolverId.concat(bigIntHex32(recordId1));
  let record2Id = resolverId.concat(bigIntHex32(recordId2));

  handleLinked(createLinkedEvent(recordId1, node, name));
  assert.fieldEquals("ENSv2ResolverLink", linkId, "record", record1Id);
  assert.fieldEquals("ENSv2ResolverLink", linkId, "recordId", "1");
  assert.fieldEquals("ENSv2ResolverLink", linkId, "active", "true");
  assert.fieldEquals("ENSv2ResolverLink", linkId, "nameDecoded", "ivan");
  assert.assertNotNull(ENSv2ResolverRecord.load(Bytes.fromHexString(record1Id)));

  // Re-link the same node to a different recordId -- same row id, fields overwritten.
  handleLinked(createLinkedEvent(recordId2, node, name));
  assert.fieldEquals("ENSv2ResolverLink", linkId, "record", record2Id);
  assert.fieldEquals("ENSv2ResolverLink", linkId, "recordId", "2");
  assert.entityCount("ENSv2ResolverLink", 1);

  // Explicit unlink (recordId 0) -- record relation cleared, active false,
  // no bogus ENSv2ResolverRecord created for recordId 0.
  let recordId0 = BigInt.zero();
  let record0Id = resolverId.concat(bigIntHex32(recordId0));
  handleLinked(createLinkedEvent(recordId0, node, name));
  assert.fieldEquals("ENSv2ResolverLink", linkId, "recordId", "0");
  assert.fieldEquals("ENSv2ResolverLink", linkId, "active", "false");
  assert.assertTrue(ENSv2ResolverRecord.load(Bytes.fromHexString(record0Id)) == null);
  // Only the two real records (recordId1, recordId2) exist -- no third for 0.
  assert.entityCount("ENSv2ResolverRecord", 2);
});

test("ContenthashUpdated and NameUpdated write directly onto ENSv2ResolverRecord", () => {
  let recordId = BigInt.fromI32(5);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let hash = Bytes.fromUTF8("ipfs://somehash");

  handleContenthashUpdated(createContenthashUpdatedEvent(recordId, hash));
  assert.fieldEquals(
    "ENSv2ResolverRecord",
    recordEntityId,
    "contenthash",
    hash.toHexString()
  );

  handleNameUpdated(createNameUpdatedEvent(recordId, "julia.eth"));
  assert.fieldEquals(
    "ENSv2ResolverRecord",
    recordEntityId,
    "primaryName",
    "julia.eth"
  );
});

test("AddressUpdated for two coinTypes on the same recordId produces two distinct ENSv2ResolverAddress rows", () => {
  let recordId = BigInt.fromI32(6);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let ethCoinType = BigInt.fromI32(60);
  let btcCoinType = BigInt.fromI32(0);
  let ethAddr = Bytes.fromI32(111);
  let btcAddr = Bytes.fromI32(222);
  let ethId = recordEntityId.concat(bigIntHex32(ethCoinType));
  let btcId = recordEntityId.concat(bigIntHex32(btcCoinType));

  handleAddressUpdated(createAddressUpdatedEvent(recordId, ethCoinType, ethAddr));
  handleAddressUpdated(createAddressUpdatedEvent(recordId, btcCoinType, btcAddr));

  assert.fieldEquals("ENSv2ResolverAddress", ethId, "addressBytes", ethAddr.toHexString());
  assert.fieldEquals("ENSv2ResolverAddress", btcId, "addressBytes", btcAddr.toHexString());
});

test("TextUpdated for two keys on the same recordId produces two distinct ENSv2ResolverText rows", () => {
  let recordId = BigInt.fromI32(7);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let avatarKeyHash = Bytes.fromI32(1);
  let urlKeyHash = Bytes.fromI32(2);
  let avatarId = recordEntityId.concat(hexOf(avatarKeyHash));
  let urlId = recordEntityId.concat(hexOf(urlKeyHash));

  handleTextUpdated(
    createTextUpdatedEvent(recordId, avatarKeyHash, "avatar", "ipfs://avatar")
  );
  handleTextUpdated(
    createTextUpdatedEvent(recordId, urlKeyHash, "url", "https://example.com")
  );

  assert.fieldEquals("ENSv2ResolverText", avatarId, "key", "avatar");
  assert.fieldEquals("ENSv2ResolverText", avatarId, "value", "ipfs://avatar");
  assert.fieldEquals("ENSv2ResolverText", urlId, "key", "url");
  assert.fieldEquals("ENSv2ResolverText", urlId, "value", "https://example.com");
});

test("DataUpdated produces ENSv2ResolverRecordData with value populated -- the real capability gain over the old (unpopulatable) ENSv2ResolverData", () => {
  let recordId = BigInt.fromI32(8);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let keyHash = Bytes.fromByteArray(crypto.keccak256(Bytes.fromUTF8("pubkey")));
  let id = recordEntityId.concat(hexOf(keyHash));
  let value = Bytes.fromUTF8("real bytes, not just a hash");

  handleRecordDataUpdated(createDataUpdatedEvent(recordId, keyHash, "pubkey", value));

  assert.fieldEquals("ENSv2ResolverRecordData", id, "key", "pubkey");
  assert.fieldEquals("ENSv2ResolverRecordData", id, "value", value.toHexString());
});

test("AddressUpdated on the same recordId+coinType twice overwrites the existing row instead of duplicating", () => {
  let recordId = BigInt.fromI32(10);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let coinType = BigInt.fromI32(60);
  let firstAddr = Bytes.fromI32(111);
  let secondAddr = Bytes.fromI32(222);
  let id = recordEntityId.concat(bigIntHex32(coinType));

  handleAddressUpdated(createAddressUpdatedEvent(recordId, coinType, firstAddr));
  assert.fieldEquals("ENSv2ResolverAddress", id, "addressBytes", firstAddr.toHexString());

  handleAddressUpdated(createAddressUpdatedEvent(recordId, coinType, secondAddr));
  assert.fieldEquals("ENSv2ResolverAddress", id, "addressBytes", secondAddr.toHexString());
  // Overwritten in place, not duplicated -- one ENSv2ResolverAddress row and
  // one ENSv2ResolverRecord row (getOrCreateRecord's own load-or-new is
  // exercised across both calls too, not just created once).
  assert.entityCount("ENSv2ResolverAddress", 1);
  assert.entityCount("ENSv2ResolverRecord", 1);
});

test("old-model and new-model events on the same resolver address don't cross-contaminate the shared ENSv2Resolver row", () => {
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();

  // Old model: NamedResource.
  let resource = BigInt.fromI32(11);
  let oldName = encodeLabel("karl");
  handleNamedResource(createNamedResourceEvent(resource, oldName));

  // New model: Linked, same resolver address.
  let recordId = BigInt.fromI32(12);
  let node = Bytes.fromI32(102);
  let newName = encodeLabel("liam");
  handleLinked(createLinkedEvent(recordId, node, newName));

  // Exactly one ENSv2Resolver row for this address, shared by both models --
  // not two separate rows, and each model's own entities are intact.
  assert.entityCount("ENSv2Resolver", 1);
  assert.assertNotNull(ENSv2Resolver.load(Bytes.fromHexString(resolverId)));

  let oldId = resolverId.concat(bigIntHex32(resource)).concat(hexOf(Bytes.fromUTF8("NAME")));
  assert.fieldEquals("ENSv2ResolverResource", oldId, "kind", "NAME");

  let linkId = resolverId.concat(hexOf(node));
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  assert.fieldEquals("ENSv2ResolverLink", linkId, "record", recordEntityId);
  assert.assertNotNull(ENSv2ResolverRecord.load(Bytes.fromHexString(recordEntityId)));
});

test("namehashFromDnsEncoded folds every label already parsed correctly when a LATER label (not the first) is truncated", () => {
  // "sub" then "eth", each well-formed, followed by a proper root
  // terminator -- this is what the malformed version below should still
  // fold down to for its first two labels.
  let subLabel = Bytes.fromUTF8("sub");
  let ethLabel = Bytes.fromUTF8("eth");
  let wellFormedOut = new Uint8Array(1 + subLabel.length + 1 + ethLabel.length + 1);
  let o = 0;
  wellFormedOut[o++] = subLabel.length as u8;
  for (let i = 0; i < subLabel.length; i++) wellFormedOut[o++] = subLabel[i];
  wellFormedOut[o++] = ethLabel.length as u8;
  for (let i = 0; i < ethLabel.length; i++) wellFormedOut[o++] = ethLabel[i];
  wellFormedOut[o++] = 0;
  let expected = namehashFromDnsEncoded(Bytes.fromUint8Array(wellFormedOut));

  // Same first two labels, but the THIRD length byte (10) claims far more
  // content than the 2 bytes actually left in the buffer -- a different
  // code path from the first-label-truncated case already covered above,
  // since offset has already advanced past two successfully-parsed labels.
  let malformedOut = new Uint8Array(1 + subLabel.length + 1 + ethLabel.length + 1 + 2);
  o = 0;
  malformedOut[o++] = subLabel.length as u8;
  for (let i = 0; i < subLabel.length; i++) malformedOut[o++] = subLabel[i];
  malformedOut[o++] = ethLabel.length as u8;
  for (let i = 0; i < ethLabel.length; i++) malformedOut[o++] = ethLabel[i];
  malformedOut[o++] = 10; // claims 10 more content bytes
  malformedOut[o++] = 0x78; // 'x'
  malformedOut[o++] = 0x79; // 'y' -- only 2 bytes actually follow, not 10

  let node = namehashFromDnsEncoded(Bytes.fromUint8Array(malformedOut));
  assert.bytesEquals(expected, node);
});

test("ABIUpdated and InterfaceUpdated produce their own child rows keyed by recordId", () => {
  let recordId = BigInt.fromI32(9);
  let resolverId = Address.fromString(PERMISSIONED_RESOLVER).toHexString();
  let recordEntityId = resolverId.concat(bigIntHex32(recordId));
  let contentType = BigInt.fromI32(1);
  let abiId = recordEntityId.concat(bigIntHex32(contentType));

  handleABIUpdated(createABIUpdatedEvent(recordId, contentType));
  assert.fieldEquals("ENSv2ResolverABI", abiId, "contentType", "1");

  let interfaceId = Bytes.fromI32(0x01ffc9a7);
  let implementer = Address.fromString(
    "0x8e8db5ccef88cca9d624701db544989c996e3211"
  );
  let interfaceEntityId = recordEntityId.concat(hexOf(interfaceId));

  handleInterfaceUpdated(
    createInterfaceUpdatedEvent(recordId, interfaceId, implementer)
  );
  assert.fieldEquals(
    "ENSv2ResolverInterface",
    interfaceEntityId,
    "implementer",
    implementer.toHexString()
  );
});

// --- namehashFromDnsEncoded bounds guard (GitHub #60, V2-only fix) ---

test("namehashFromDnsEncoded on an empty buffer returns ROOT_NODE instead of crashing", () => {
  let empty = Bytes.fromUint8Array(new Uint8Array(0));
  let node = namehashFromDnsEncoded(empty);
  assert.bytesEquals(
    Bytes.fromHexString(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    ),
    node
  );
});

test("namehashFromDnsEncoded on a buffer with no trailing zero-length terminator still folds every real label", () => {
  // "alice" with its length prefix but no root terminator byte -- a
  // truncated encoding, distinct from the malformed-length case below.
  let labelBytes = Bytes.fromUTF8("alice");
  let out = new Uint8Array(labelBytes.length + 1);
  out[0] = labelBytes.length as u8;
  for (let i = 0; i < labelBytes.length; i++) {
    out[i + 1] = labelBytes[i];
  }
  let noTerminator = Bytes.fromUint8Array(out);

  let node = namehashFromDnsEncoded(noTerminator);
  assert.bytesEquals(namehashFromDnsEncoded(encodeLabel("alice")), node);
});

test("namehashFromDnsEncoded on a label length exceeding the remaining buffer stops early instead of reading out of bounds", () => {
  // Claims a 10-byte label but only 3 content bytes actually follow.
  let out = new Uint8Array(4);
  out[0] = 10;
  out[1] = 0x61; // 'a'
  out[2] = 0x62; // 'b'
  out[3] = 0x63; // 'c'
  let malformed = Bytes.fromUint8Array(out);

  // Must not trap/crash -- and since the one (malformed) label never
  // parses, folds down to ROOT_NODE, same as the empty-buffer case.
  let node = namehashFromDnsEncoded(malformed);
  assert.bytesEquals(
    Bytes.fromHexString(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    ),
    node
  );
});
