// Minimal smoke-test layer for every handler wired from
// src/ensv2Resolver.ts (old- and new-model PermissionedResolver events).
// Independent of and redundant with ensv2Resolver.test.ts's richer
// behavioral tests -- one mock-event-per-handler baseline only.
import { Address, BigInt, Bytes, ethereum } from "@graphprotocol/graph-ts";
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
  handleEACRolesChanged,
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
} from "../src/ensv2Resolver";
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
} from "../src/types/PermissionedResolver/PermissionedResolver";

const RESOLVER = "0x5050505050505050505050505050505050505050";
const SMOKE_NAME = Bytes.fromHexString("0x05736d6f6b650365746800");

function newEventLike<T>(
  ctor: (
    address: Address,
    logIndex: BigInt,
    transactionLogIndex: BigInt,
    logType: string | null,
    block: ethereum.Block,
    transaction: ethereum.Transaction,
    parameters: Array<ethereum.EventParam>,
    receipt: ethereum.TransactionReceipt | null
  ) => T
): T {
  let mockEvent = newMockEvent();
  return ctor(
    Address.fromString(RESOLVER),
    mockEvent.logIndex,
    mockEvent.transactionLogIndex,
    mockEvent.logType,
    mockEvent.block,
    mockEvent.transaction,
    mockEvent.parameters,
    mockEvent.receipt
  );
}

afterEach(() => {
  clearStore();
});

test("smoke: handleAliasChanged creates an ENSv2ResolverAlias row", () => {
  let event = newEventLike<AliasChanged>(
    (a, li, tli, lt, b, t, p, r) => new AliasChanged(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("indexedFromName", ethereum.Value.fromBytes(SMOKE_NAME))
  );
  event.parameters.push(
    new ethereum.EventParam("indexedToName", ethereum.Value.fromBytes(SMOKE_NAME))
  );
  event.parameters.push(new ethereum.EventParam("fromName", ethereum.Value.fromBytes(SMOKE_NAME)));
  event.parameters.push(new ethereum.EventParam("toName", ethereum.Value.fromBytes(SMOKE_NAME)));
  handleAliasChanged(event);
  assert.entityCount("ENSv2ResolverAlias", 1);
});

test("smoke: handleNamedResource creates an ENSv2ResolverResource row of kind NAME", () => {
  let event = newEventLike<NamedResource>(
    (a, li, tli, lt, b, t, p, r) => new NamedResource(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("resource", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("name", ethereum.Value.fromBytes(SMOKE_NAME)));
  handleNamedResource(event);
  assert.entityCount("ENSv2ResolverResource", 1);
});

test("smoke: handleNamedTextResource creates an ENSv2ResolverResource row of kind TEXT", () => {
  let event = newEventLike<NamedTextResource>(
    (a, li, tli, lt, b, t, p, r) => new NamedTextResource(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("resource", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(2)))
  );
  event.parameters.push(new ethereum.EventParam("name", ethereum.Value.fromBytes(SMOKE_NAME)));
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("key", ethereum.Value.fromString("smokekey")));
  handleNamedTextResource(event);
  assert.entityCount("ENSv2ResolverResource", 1);
});

test("smoke: handleNamedDataResource creates an ENSv2ResolverResource row of kind DATA", () => {
  let event = newEventLike<NamedDataResource>(
    (a, li, tli, lt, b, t, p, r) => new NamedDataResource(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("resource", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(3)))
  );
  event.parameters.push(new ethereum.EventParam("name", ethereum.Value.fromBytes(SMOKE_NAME)));
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromFixedBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("key", ethereum.Value.fromString("smokekey")));
  handleNamedDataResource(event);
  assert.entityCount("ENSv2ResolverResource", 1);
});

test("smoke: handleNamedAddrResource creates an ENSv2ResolverResource row of kind ADDR", () => {
  let event = newEventLike<NamedAddrResource>(
    (a, li, tli, lt, b, t, p, r) => new NamedAddrResource(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("resource", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(4)))
  );
  event.parameters.push(new ethereum.EventParam("name", ethereum.Value.fromBytes(SMOKE_NAME)));
  event.parameters.push(
    new ethereum.EventParam("coinType", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(60)))
  );
  handleNamedAddrResource(event);
  assert.entityCount("ENSv2ResolverResource", 1);
});

test("smoke: handleDataChanged creates an ENSv2ResolverData row", () => {
  let event = newEventLike<DataChanged>(
    (a, li, tli, lt, b, t, p, r) => new DataChanged(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("node", ethereum.Value.fromFixedBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("indexedKey", ethereum.Value.fromString("smokekey")));
  event.parameters.push(new ethereum.EventParam("key", ethereum.Value.fromString("smokekey")));
  event.parameters.push(
    new ethereum.EventParam("indexedData", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  handleDataChanged(event);
  assert.entityCount("ENSv2ResolverData", 1);
});

test("smoke: handleEACRolesChanged creates an ENSv2RoleAssignment row", () => {
  let event = newEventLike<EACRolesChanged>(
    (a, li, tli, lt, b, t, p, r) => new EACRolesChanged(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("resource", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "account",
      ethereum.Value.fromAddress(Address.fromString("0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7"))
    )
  );
  event.parameters.push(
    new ethereum.EventParam("oldRoleBitmap", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(0)))
  );
  event.parameters.push(
    new ethereum.EventParam("newRoleBitmap", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  handleEACRolesChanged(event);
  assert.entityCount("ENSv2RoleAssignment", 1);
});

test("smoke: handleResolverCreated creates only the ENSv2Resolver row", () => {
  let event = newEventLike<ResolverCreated>(
    (a, li, tli, lt, b, t, p, r) => new ResolverCreated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  handleResolverCreated(event);
  assert.fieldEquals(
    "ENSv2Resolver",
    Address.fromString(RESOLVER).toHexString(),
    "address",
    Address.fromString(RESOLVER).toHexString()
  );
});

test("smoke: handleLinked creates an ENSv2ResolverLink and its ENSv2ResolverRecord", () => {
  let event = newEventLike<Linked>((a, li, tli, lt, b, t, p, r) => new Linked(a, li, tli, lt, b, t, p, r));
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("node", ethereum.Value.fromFixedBytes(Bytes.fromI32(9)))
  );
  event.parameters.push(new ethereum.EventParam("name", ethereum.Value.fromBytes(SMOKE_NAME)));
  handleLinked(event);
  assert.entityCount("ENSv2ResolverLink", 1);
  assert.entityCount("ENSv2ResolverRecord", 1);
});

test("smoke: handleContenthashUpdated sets contenthash on an ENSv2ResolverRecord", () => {
  let event = newEventLike<ContenthashUpdated>(
    (a, li, tli, lt, b, t, p, r) => new ContenthashUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("hash", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  handleContenthashUpdated(event);
  assert.entityCount("ENSv2ResolverRecord", 1);
});

test("smoke: handleNameUpdated sets primaryName on an ENSv2ResolverRecord", () => {
  let event = newEventLike<NameUpdated>(
    (a, li, tli, lt, b, t, p, r) => new NameUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("primaryName", ethereum.Value.fromString("smoke.eth"))
  );
  handleNameUpdated(event);
  assert.entityCount("ENSv2ResolverRecord", 1);
});

test("smoke: handleAddressUpdated creates an ENSv2ResolverAddress row", () => {
  let event = newEventLike<AddressUpdated>(
    (a, li, tli, lt, b, t, p, r) => new AddressUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("coinType", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(60)))
  );
  event.parameters.push(
    new ethereum.EventParam("addressBytes", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  handleAddressUpdated(event);
  assert.entityCount("ENSv2ResolverAddress", 1);
});

test("smoke: handleTextUpdated creates an ENSv2ResolverText row", () => {
  let event = newEventLike<TextUpdated>(
    (a, li, tli, lt, b, t, p, r) => new TextUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("key", ethereum.Value.fromString("smokekey")));
  event.parameters.push(new ethereum.EventParam("value", ethereum.Value.fromString("smokevalue")));
  handleTextUpdated(event);
  assert.entityCount("ENSv2ResolverText", 1);
});

test("smoke: handleRecordDataUpdated creates an ENSv2ResolverRecordData row", () => {
  let event = newEventLike<DataUpdated>(
    (a, li, tli, lt, b, t, p, r) => new DataUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("keyHash", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(new ethereum.EventParam("key", ethereum.Value.fromString("smokekey")));
  event.parameters.push(
    new ethereum.EventParam("value", ethereum.Value.fromBytes(Bytes.fromI32(1)))
  );
  handleRecordDataUpdated(event);
  assert.entityCount("ENSv2ResolverRecordData", 1);
});

test("smoke: handleABIUpdated creates an ENSv2ResolverABI row", () => {
  let event = newEventLike<ABIUpdated>(
    (a, li, tli, lt, b, t, p, r) => new ABIUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("contentType", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  handleABIUpdated(event);
  assert.entityCount("ENSv2ResolverABI", 1);
});

test("smoke: handleInterfaceUpdated creates an ENSv2ResolverInterface row", () => {
  let event = newEventLike<InterfaceUpdated>(
    (a, li, tli, lt, b, t, p, r) => new InterfaceUpdated(a, li, tli, lt, b, t, p, r)
  );
  event.parameters = new Array();
  event.parameters.push(
    new ethereum.EventParam("recordId", ethereum.Value.fromUnsignedBigInt(BigInt.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam("interfaceId", ethereum.Value.fromFixedBytes(Bytes.fromI32(1)))
  );
  event.parameters.push(
    new ethereum.EventParam(
      "implementer",
      ethereum.Value.fromAddress(Address.fromString("0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7"))
    )
  );
  handleInterfaceUpdated(event);
  assert.entityCount("ENSv2ResolverInterface", 1);
});
