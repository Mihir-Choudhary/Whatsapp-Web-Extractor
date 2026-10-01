// proto_patch.js -- teach Baileys' protobuf the fields the REAL WhatsApp Web client sends.
//
// Baileys' generated proto is behind the live client. The field numbers below are read out of
// WhatsApp Web's own shipped bundle -- fetch the current one from static.whatsapp.net (the loader
// names it in web.whatsapp.com's HTML) and search for `HistorySyncOnDemandRequest`; the same schema
// is also in the browser profile's Code Cache. They are NOT guessed. The specs are:
//
//   Message$PeerDataOperationRequestMessage$HistorySyncOnDemandRequest
//     chatJid:[1,STRING] oldestMsgId:[2,STRING] oldestMsgFromMe:[3,BOOL]
//     onDemandMsgCount:[4,INT32] oldestMsgTimestampMs:[5,INT64]
//     accountLid:[6,STRING] supportInlineResponse:[7,BOOL]        <- Baileys has no field 7
//
//   Baileys 6.7.24 DOES have field 6 and encodes it when present, but the reference client never
//   sets accountLid on this request, so history_extract.js deliberately omits it. Only field 7 is
//   missing from Baileys, which is what this file adds.
//
//   Message$PeerDataOperationRequestMessage$FullHistorySyncOnDemandRequest
//     requestMetadata:[1,MESSAGE] historySyncConfig:[2,MESSAGE]
//     fullHistorySyncOnDemandConfig:[3,MESSAGE]                   <- Baileys has no field 3
//
//   Message$FullHistorySyncOnDemandConfig
//     historyFromTimestamp:[1,UINT64] historyDurationDays:[2,UINT32]
//
//   Message$PeerDataOperationRequestMessage$HistorySyncChunkRetryRequest
//     syncType:[1,ENUM] chunkOrder:[2,UINT32] chunkNotificationId:[3,STRING] regenerateChunk:[4,BOOL]
//
// So rather than guess a wire number (which is what "the numbering differs" would have reduced us
// to), the numbers come from the client itself. Each field is appended by wrapping the generated
// encoder and writing the tag by hand, which is safe in both directions: protobuf readers ignore
// fields they do not know, so a peer on an older schema is unaffected.
//
// Tag = (fieldNumber << 3) | wireType.  varint = 0, length-delimited = 2.
//
// IMPORTANT constraint on how these wrappers are used. They read the extra field off the object
// handed to encode(), so they only fire for a PLAIN object. protobufjs' `Type.fromObject()` drops
// properties the generated type does not declare, so `H.encode(H.fromObject(o))` silently loses
// field 7 while `H.encode(o)` keeps it. Baileys passes the plain object tree straight through
// (sendPeerDataOperationMessage -> relayMessage -> proto.Message.encode), so the field does reach
// the wire -- verified end to end: encoding the full nested ProtocolMessage yields a trailing 3801
// (field 7, varint, true). If a future refactor normalises messages through fromObject() first,
// this patch goes quiet without failing, so that byte check is the thing to re-run.
'use strict';

function patch(B) {
  const P = B.proto && B.proto.Message && B.proto.Message.PeerDataOperationRequestMessage;
  if (!P) throw new Error('unexpected Baileys proto shape: PeerDataOperationRequestMessage missing');
  const done = [];

  // --- HistorySyncOnDemandRequest.supportInlineResponse = 7, BOOL ---------------------------
  const H = P.HistorySyncOnDemandRequest;
  if (H && !H.__wawfPatched) {
    const orig = H.encode.bind(H);
    H.encode = (m, w) => {
      const wr = orig(m, w);
      if (m && m.supportInlineResponse !== undefined && m.supportInlineResponse !== null) {
        wr.uint32((7 << 3) | 0).bool(!!m.supportInlineResponse);
      }
      return wr;
    };
    H.__wawfPatched = true;
    done.push('HistorySyncOnDemandRequest.supportInlineResponse(7,bool)');
  }

  // --- FullHistorySyncOnDemandRequest.fullHistorySyncOnDemandConfig = 3, MESSAGE ------------
  // The nested Message$FullHistorySyncOnDemandConfig is written inline, since Baileys has no
  // generated type for it: historyFromTimestamp(1,uint64), historyDurationDays(2,uint32).
  const F = P.FullHistorySyncOnDemandRequest;
  if (F && !F.__wawfPatched) {
    const orig = F.encode.bind(F);
    F.encode = (m, w) => {
      const wr = orig(m, w);
      const c = m && m.fullHistorySyncOnDemandConfig;
      if (c) {
        wr.uint32((3 << 3) | 2).fork();
        if (c.historyFromTimestamp !== undefined && c.historyFromTimestamp !== null) {
          wr.uint32((1 << 3) | 0).uint64(c.historyFromTimestamp);
        }
        if (c.historyDurationDays !== undefined && c.historyDurationDays !== null) {
          wr.uint32((2 << 3) | 0).uint32(c.historyDurationDays);
        }
        wr.ldelim();
      }
      return wr;
    };
    F.__wawfPatched = true;
    done.push('FullHistorySyncOnDemandRequest.fullHistorySyncOnDemandConfig(3,msg{1:uint64,2:uint32})');
  }

  // --- PeerDataOperationRequestMessage.historySyncChunkRetryRequest ------------------------
  // Absent from Baileys entirely. Its field number inside PeerDataOperationRequestMessage is not
  // in the spec dump we have, so it is NOT guessed here -- exposed as a helper that builds the
  // inner message only, for when the outer number is known.
  function encodeChunkRetry({ syncType, chunkOrder, chunkNotificationId, regenerateChunk }) {
    // (This used to gate creating the Writer on the presence of an unrelated generated type,
    // PlaceholderMessageResendRequest, and throw "protobufjs Writer unavailable" if it was absent.
    // That check was meaningless: protobufjs is a hard dependency of Baileys and the two have
    // nothing to do with each other.)
    const w = require('protobufjs/minimal').Writer.create();
    if (syncType !== undefined) w.uint32((1 << 3) | 0).int32(syncType);
    if (chunkOrder !== undefined) w.uint32((2 << 3) | 0).uint32(chunkOrder);
    if (chunkNotificationId !== undefined) w.uint32((3 << 3) | 2).string(chunkNotificationId);
    if (regenerateChunk !== undefined) w.uint32((4 << 3) | 0).bool(!!regenerateChunk);
    return w.finish();
  }

  return { patched: done, encodeChunkRetry };
}

module.exports = { patch };
