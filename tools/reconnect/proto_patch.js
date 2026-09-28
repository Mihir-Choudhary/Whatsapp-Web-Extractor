// proto_patch.js -- teach Baileys' protobuf the fields the REAL WhatsApp Web client sends.
//
// Baileys' generated proto is behind the live client. Read out of WhatsApp Web's own bundle
// (analysis/wa_chunk_249.js, and the same schema is in the browser's Code Cache), the specs are:
//
//   Message$PeerDataOperationRequestMessage$HistorySyncOnDemandRequest
//     chatJid:[1,STRING] oldestMsgId:[2,STRING] oldestMsgFromMe:[3,BOOL]
//     onDemandMsgCount:[4,INT32] oldestMsgTimestampMs:[5,INT64]
//     accountLid:[6,STRING] supportInlineResponse:[7,BOOL]        <- Baileys has no field 7
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
    const w = B.proto.Message.PeerDataOperationRequestMessage.PlaceholderMessageResendRequest
      ? require('protobufjs/minimal').Writer.create()
      : null;
    if (!w) throw new Error('protobufjs Writer unavailable');
    if (syncType !== undefined) w.uint32((1 << 3) | 0).int32(syncType);
    if (chunkOrder !== undefined) w.uint32((2 << 3) | 0).uint32(chunkOrder);
    if (chunkNotificationId !== undefined) w.uint32((3 << 3) | 2).string(chunkNotificationId);
    if (regenerateChunk !== undefined) w.uint32((4 << 3) | 0).bool(!!regenerateChunk);
    return w.finish();
  }

  return { patched: done, encodeChunkRetry };
}

module.exports = { patch };
