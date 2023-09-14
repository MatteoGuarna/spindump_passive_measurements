
//
//
//  ////////////////////////////////////////////////////////////////////////////////////
//  /////////                                                                ///////////
//  //////       SSS    PPPP    I   N    N   DDDD    U   U   M   M   PPPP         //////
//  //          S       P   P   I   NN   N   D   D   U   U   MM MM   P   P            //
//  /            SSS    PPPP    I   N NN N   D   D   U   U   M M M   PPPP              /
//  //              S   P       I   N   NN   D   D   U   U   M   M   P                //
//  ////         SSS    P       I   N    N   DDDD     UUU    M   M   P            //////
//  /////////                                                                ///////////
//  ////////////////////////////////////////////////////////////////////////////////////
//
//  SPINDUMP (C) 2018-2019 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_seq.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Initialize a sequence number tracker. A sequence number tracker
// records sent out sequence numbers that are 32 bits long, remembers
// the time they were sent, and then can match an acknowledgment of
// that sequence number These trackers are used in the TCP protocol
// analyzer. There's two trackers, one for each direction.
//

void
spindump_seqtracker_initialize(struct spindump_seqtracker* tracker) {
  spindump_assert(tracker != 0);
  memset(tracker,0,sizeof(*tracker));
  tracker->seqindex = 0;
}

//
// Add a new sequence number to the tracker
//

void
spindump_seqtracker_add(struct spindump_seqtracker* tracker,
                        struct timeval* ts,
                        tcp_ts ts_val,
                        tcp_seq seq,
                        unsigned int payloadlen,
                        int finset) {
  spindump_assert(tracker != 0);
  spindump_assert(tracker->seqindex < spindump_seqtracker_nstored);
  spindump_assert(finset == 0 || finset == 1);
  tracker->stored[tracker->seqindex].valid = 1;
  tracker->stored[tracker->seqindex].acked = 0;
  tracker->stored[tracker->seqindex].received = *ts;
  tracker->stored[tracker->seqindex].ts_val = ts_val;
  tracker->stored[tracker->seqindex].seq = seq;
  tracker->stored[tracker->seqindex].len = payloadlen;
  tracker->stored[tracker->seqindex].finset = finset;
  tracker->seqindex++;
  tracker->seqindex %= spindump_seqtracker_nstored;
  spindump_assert(tracker->seqindex < spindump_seqtracker_nstored);
}

//
// Determine what time the request message was sent for a given
// sequence number. Return a pointer to that time, or 0 if no such
// sequence number has been seen.
//

struct timeval*
spindump_seqtracker_ackto(struct spindump_seqtracker* tracker,
                          tcp_seq seq,
                          tcp_seq sack,
                          tcp_ts ts_ecr,
                          struct timeval* t,
                          tcp_seq* sentSeq,
                          int* sentFin) {
  
  //
  // The highest acked sequence number is either given by the cumulative acknowledgement
  // field in the TCP header, or by the right edge of the first sack block.
  //

  tcp_seq highestacked = sack > seq ? sack : seq;
  highestacked -= 1;

  spindump_deepdebugf("compare cumulative ack %u to largest selective ack %u. highest ack = %u",
                        seq, sack, highestacked);

  spindump_assert(sentSeq != 0);
  
  //
  // Find the earliest sent packet that this could be an
  // acknowledgment for.
  // 
  
  struct spindump_seqstore* chosen = 0;
  for (unsigned int i = 0; i < spindump_seqtracker_nstored; i++) {
    
    struct spindump_seqstore* candidate = &tracker->stored[i];

    //
    // Is this entry in use? If not, go to next
     // 

    if (!candidate->valid) continue;
    
    //
    // Is this previously seen TCP segment the one
    // acked by sequence number "seq"?
    // 
    
    spindump_deepdebugf("compare received ACK %u (%u) to candidate earlier sent SEQ %u..%u at -%llu ago len %u valid %u acked %u",
                        highestacked, seq,
                        candidate->seq, candidate->seq + candidate->len,
                        spindump_timediffinusecs(t,
                                                 &candidate->received),
                        candidate->len,
                        candidate->valid,
                        candidate->acked);
    
    if (candidate->seq == highestacked ||
        (candidate->seq <= highestacked &&
         highestacked < candidate->seq + candidate->len)) {
      
      //
      // It is. Now see if this is the earliest one.
      // 
      
      if (chosen == 0) {
        spindump_deepdebugf("first matching candidate chosen");
        chosen = candidate;
     } else if (spindump_isearliertime(&candidate->received,&chosen->received)) {
        spindump_deepdebugf("earlier matching candidate chosen");
        chosen = candidate;
      }
    }
  }
  
  if (chosen != 0) {
    
    //
    // Found. Return the time when that packet was sent.
    // But first, clear the sequence stores from all entries
    // sent earlier than the one that we found. And clear this
    // entry too.
    // 

    for (unsigned int j = 0; j < spindump_seqtracker_nstored; j++) {
      struct spindump_seqstore* other = &tracker->stored[j];
      if (other->valid && !other->acked && spindump_isearliertime(&chosen->received,&other->received)) {
        other->acked = 1;
      }
    }

    //
    // Did we already ack this earlier? If yes, we can't say anything about RTT.
    //

    if (chosen->acked) {
      *sentSeq = chosen->seq;
      *sentFin = chosen->finset;
      return(0);
    }

    //
    // Previously unseen ack, report the time.
    //
    
    chosen->acked = 1;
    *sentSeq = chosen->seq;
    *sentFin = chosen->finset;
    return(&chosen->received);
    
  } else {
    
    //
    // Not found
    // 
    
    *sentSeq = 0;
    *sentFin = 0;
    return(0);
    
  }
}

//
// Uninitialize the sequence number tracker object.
//

void
spindump_seqtracker_uninitialize(struct spindump_seqtracker* tracker) {
  spindump_assert(tracker != 0);
  // no-op
}
