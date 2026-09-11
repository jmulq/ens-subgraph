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
