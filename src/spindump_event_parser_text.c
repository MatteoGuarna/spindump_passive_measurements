
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "spindump_util.h"
#include "spindump_event.h"
#include "spindump_event_parser_text.h"
#include "spindump_connections.h"

//
// Actual code --------------------------------------------------------------------------------
//

//
// Take a buffer of data in "buffer" (whose length is given in
// "length") and parse it as a textual event description from
// Spindump, placing the result in the output parqmeter "event".
//
// If successful, return 1, upon no non-whitespace input to read in
// the buffer, return 0 for EOF, and upon parsing error return -1.
//
// In any case, set the output parameter "consumed" to the number of
// bytes consumed from the buffer.
//

int
spindump_event_parser_text_parse(const char* buffer,
                                 size_t length,
                                 struct spindump_event* event,
                                 size_t* consumed) {
  return(0); // ...
}
