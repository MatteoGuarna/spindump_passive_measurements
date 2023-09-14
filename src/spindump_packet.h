
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
//  SPINDUMP (C) 2018-2020 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

#ifndef SPINDUMP_PACKET_H
#define SPINDUMP_PACKET_H

//
// Includes -----------------------------------------------------------------------------------
//

#include <sys/time.h>
#include "spindump_protocols.h"

//
// Capture data structures --------------------------------------------------------------------
//

struct spindump_packet {
  unsigned int etherlen;                       // The size of the packet, including the
                                               // Ethernet header
  unsigned int caplen;                         // How much of the packet was captured
  struct timeval timestamp;                    // Reception time of the packet
  const unsigned char* contents;               // The whole received packet
  spindump_counter_32bit analyzerHandlerCalls; // A counter, used to determine whether to call
                                               // an extra handler, in case no other handler was
                                               // called
};

//
// Packet module API interface -----------------------------------------
//

int
spindump_packet_isvalid(struct spindump_packet* packet);

#endif // SPINDUMP_PACKET_H
