// Re-exports from the generated protobuf static module.
//
// `scripts/fetch-protos.ts` runs `pbjs` + `pbts` to emit `protos/generated.js`
// (runtime classes) and `protos/generated.d.ts` (types). We consume both
// directly — no runtime `.proto` parsing, and the generated message classes
// already carry correctly typed `decode`/`encode`/`create`/`toObject`/etc.

import { signalservice } from "../protos/generated.js";

// ---- Message classes (runtime) ----
export const ProvisionEnvelope = signalservice.ProvisionEnvelope;
export const ProvisionMessage = signalservice.ProvisionMessage;
export const DeviceName = signalservice.DeviceName;
export const Content = signalservice.Content;
export const SyncMessage = signalservice.SyncMessage;
export const DataMessage = signalservice.DataMessage;
export const Envelope = signalservice.Envelope;
export const AttachmentPointer = signalservice.AttachmentPointer;
export const ContactDetails = signalservice.ContactDetails;

// ---- Interface types ----
export type IContent = signalservice.IContent;
export type ISyncMessage = signalservice.ISyncMessage;
export type IDataMessage = signalservice.IDataMessage;
export type IEnvelope = signalservice.IEnvelope;
export type IAttachmentPointer = signalservice.IAttachmentPointer;
export type IContactDetails = signalservice.IContactDetails;
export type IProvisionEnvelope = signalservice.IProvisionEnvelope;
export type IProvisionMessage = signalservice.IProvisionMessage;
export type IDeviceName = signalservice.IDeviceName;

// ---- Enums (runtime + type) ----
export const EnvelopeType = signalservice.Envelope.Type;
export type EnvelopeType = signalservice.Envelope.Type;
export const SyncRequestType = signalservice.SyncMessage.Request.Type;
export type SyncRequestType = signalservice.SyncMessage.Request.Type;
export const ReceiptType = signalservice.ReceiptMessage.Type;
export type ReceiptType = signalservice.ReceiptMessage.Type;
