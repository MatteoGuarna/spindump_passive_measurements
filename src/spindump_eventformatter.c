
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
//  SPINDUMP (C) 2018-2021 BY ERICSSON RESEARCH
//  AUTHOR: JARI ARKKO
//
// 

//
// Includes -----------------------------------------------------------------------------------
//

#include <stdio.h>
#include <string.h>
#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_connections.h"
#include "spindump_remote_client.h"
#include "spindump_eventformatter.h"
#include "spindump_eventformatter_text.h"
#include "spindump_eventformatter_json.h"
#include "spindump_eventformatter_qlog.h"
#include "spindump_event.h"

//
// Function prototypes ------------------------------------------------------------------------
//

static unsigned long
spindump_eventformatter_measurement_beginlength(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter);
static const uint8_t*
spindump_eventformatter_measurement_beginaux(struct spindump_eventformatter* formatter,
                                             unsigned long* length);
static const uint8_t*
spindump_eventformatter_measurement_midaux(struct spindump_eventformatter* formatter,
                                           unsigned long* length);
static unsigned long
spindump_eventformatter_measurement_endlength(struct spindump_eventformatter* formatter);
static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter);
static const uint8_t*
spindump_eventformatter_measurement_endaux(struct spindump_eventformatter* formatter,
                                           unsigned long* length);
static void
spindump_eventformatter_measurement_one(struct spindump_analyze* state,
                                        void* handlerData,
                                        void** handlerConnectionData,
                                        spindump_analyze_event event,
                                        const struct timeval* timestamp,
                                        const int fromResponder,
                                        const unsigned int ipPacketLength,
                                        struct spindump_packet* packet,
                                        struct spindump_connection* connection);
static struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
                                   enum spindump_eventformatter_outputformat format,
                                   struct spindump_reverse_dns* querier,
                                   int reportSpins,
                                   int reportSpinFlips,
                                   int reportRtLoss,
                                   int reportQrLoss,
                                   int reportQlLoss,
                                   int reportPackets,
                                   int reportNotes,
                                   int anonymizeLeft,
                                   int anonymizeRight,
                                   int aggregatesOnly,
                                   int averageRtts,
                                   int minimumRtts,
                                   unsigned int filterExceptionalValuesPercentage);
static const char*
spindump_eventformatter_mediatype(enum spindump_eventformatter_outputformat format);
static void
spindump_eventformatter_deliverdata_remoteblock(struct spindump_eventformatter* formatter,
                                                unsigned long length,
                                                const uint8_t* data);

//
// Actual code --------------------------------------------------------------------------------
//

static struct spindump_eventformatter*
spindump_eventformatter_initialize(struct spindump_analyze* analyzer,
                                   enum spindump_eventformatter_outputformat format,
                                   struct spindump_reverse_dns* querier,
                                   int reportSpins,
                                   int reportSpinFlips,
                                   int reportRtLoss,
                                   int reportQrLoss,
                                   int reportQlLoss,
                                   int reportPackets,
                                   int reportNotes,
                                   int anonymizeLeft,
                                   int anonymizeRight,
                                   int aggregatesOnly,
                                   int averageRtts,
                                   int minimumRtts,
                                   unsigned int filterExceptionalValuesPercentage) {
  
  //
  // Allocate an object
  //

  spindump_deepdebugf("eventformatter_initialize");
  unsigned int siz = sizeof(struct spindump_eventformatter);
  struct spindump_eventformatter* formatter = (struct spindump_eventformatter*)spindump_malloc(siz);
  if (formatter == 0) {
    spindump_errorf("cannot allocate memory for the event formatter (%u bytes)", siz);
    return(0);
  }

  //
  // Fill in the contents
  //

  spindump_deepdebugf("eventformatter_initialize pt. 2");
  memset(formatter,0,sizeof(*formatter));
  formatter->analyzer = analyzer;
  formatter->format = format;
  formatter->file = 0;
  formatter->nRemotes = 0;
  formatter->remotes = 0;
  formatter->blockSize = 0;
  formatter->querier = querier;
  formatter->reportSpins = reportSpins;
  formatter->reportSpinFlips = reportSpinFlips;
  formatter->reportRtLoss = reportRtLoss;
  formatter->reportQrLoss = reportQrLoss;
  formatter->reportQlLoss = reportQlLoss;
  formatter->reportPackets = reportPackets;
  formatter->reportNotes = reportNotes;
  formatter->anonymizeLeft = anonymizeLeft;
  formatter->anonymizeRight = anonymizeRight;
  formatter->aggregatesOnly = aggregatesOnly;
  formatter->averageRtts = averageRtts;
  formatter->minimumRtts = minimumRtts;
  spindump_deepdeepdebugf("spindump_eventformatter_initialize: averageRtts set to %u", formatter->averageRtts);
  formatter->filterExceptionalValuesPercentage = filterExceptionalValuesPercentage;
  spindump_deepdeepdebugf("filter filterExceptionalValuesPercentage = %u", formatter->filterExceptionalValuesPercentage);
  
  //
  // Register a handler for relevant events
  //

  spindump_deepdeepdebugf("spindump_eventformatter_initialize registering a handler");
  spindump_analyze_registerhandler(analyzer,
                                   spindump_analyze_event_alllegal,
                                   0,
                                   spindump_eventformatter_measurement_one,
                                   formatter);

  //
  // Done. Return the object.
  //

  spindump_deepdebugf("eventformatter_initialize pt.3");
  return(formatter);
}

struct spindump_eventformatter*
spindump_eventformatter_initialize_file(struct spindump_analyze* analyzer,
                                        enum spindump_eventformatter_outputformat format,
                                        FILE* file,
                                        struct spindump_reverse_dns* querier,
                                        int reportSpins,
                                        int reportSpinFlips,
                                        int reportRtLoss,
                                        int reportQrLoss,
                                        int reportQlLoss,
                                        int reportPackets,
                                        int reportNotes,
                                        int anonymizeLeft,
                                        int anonymizeRight,
                                        int aggregatesOnly,
                                        int averageRtts,
                                        int minimumRtts,
                                        unsigned int filterExceptionalValuesPercentage) {
  
  //
  // Call the basic eventformatter initialization
  //

  struct spindump_eventformatter* formatter = spindump_eventformatter_initialize(analyzer,
                                                                                 format,
                                                                                 querier,
                                                                                 reportSpins,
                                                                                 reportSpinFlips,
                                                                                 reportRtLoss,
                                                                                 reportQrLoss,
                                                                                 reportQlLoss,
                                                                                 reportPackets,
                                                                                 reportNotes,
                                                                                 anonymizeLeft,
                                                                                 anonymizeRight,
                                                                                 aggregatesOnly,
                                                                                 averageRtts,
                                                                                 minimumRtts,
                                                                                 filterExceptionalValuesPercentage);
  if (formatter == 0) {
    return(0);
  }
  
  //
  // Do the file-specific setup
  //

  formatter->file = file;
  
  //
  // Start the format by adding whatever prefix is needed in the output stream
  //
  
  spindump_eventformatter_measurement_begin(formatter);
  
  //
  // Done. Return the object.
  //

  return(formatter);
}

struct spindump_eventformatter*
spindump_eventformatter_initialize_remote(struct spindump_analyze* analyzer,
                                          enum spindump_eventformatter_outputformat format,
                                          unsigned int nRemotes,
                                          struct spindump_remote_client** remotes,
                                          unsigned long blockSize,
                                          struct spindump_reverse_dns* querier,
                                          int reportSpins,
                                          int reportSpinFlips,
                                          int reportRtLoss,
                                          int reportQrLoss,
                                          int reportQlLoss,
                                          int reportPackets,
                                          int reportNotes,
                                          int anonymizeLeft,
                                          int anonymizeRight,
                                          int aggregatesOnly,
                                          int averageRtts,
                                          int minimumRtts,
                                          unsigned int filterExceptionalValuesPercentage) {
  
  //
  // Call the basic eventformatter initialization
  //

  spindump_deepdebugf("eventformatter_initialize_remote");
  struct spindump_eventformatter* formatter = spindump_eventformatter_initialize(analyzer,
                                                                                 format,
                                                                                 querier,
                                                                                 reportSpins,
                                                                                 reportSpinFlips,
                                                                                 reportRtLoss,
                                                                                 reportQrLoss,
                                                                                 reportQlLoss,
                                                                                 reportPackets,
                                                                                 reportNotes,
                                                                                 anonymizeLeft,
                                                                                 anonymizeRight,
                                                                                 aggregatesOnly,
                                                                                 averageRtts,
                                                                                 minimumRtts,
                                                                                 filterExceptionalValuesPercentage);
  if (formatter == 0) {
    return(0);
  }
  
  //
  // Do the remote-specific setup
  //

  spindump_deepdebugf("eventformatter_initialize_remote pt. 2");
  formatter->nRemotes = nRemotes;
  formatter->remotes = remotes;
  formatter->blockSize = blockSize;
  
  //
  // Allocate the block buffer (if we can)
  //

  if (formatter->blockSize > 0) {
    formatter->block = (uint8_t*)spindump_malloc(formatter->blockSize);
    if (formatter->block == 0) {
      spindump_errorf("cannot allocate memory for the event formatter (%lu bytes)", formatter->blockSize);
      spindump_free(formatter);
      return(0);
    }
    formatter->bytesInBlock = 0;
  }

  //
  // Check the preamble and postamble lengths
  //

  spindump_deepdebugf("eventformatter_initialize_remote pt.3");
  if (formatter->blockSize > 0 &&
      (spindump_eventformatter_measurement_beginlength(formatter) +
       spindump_eventformatter_measurement_endlength(formatter) >= formatter->blockSize ||
       spindump_eventformatter_measurement_beginlength(formatter) > spindump_eventformatter_maxpreamble ||
       spindump_eventformatter_measurement_beginlength(formatter) > spindump_eventformatter_maxpostamble)) {
    spindump_errorf("preamble and postamble lengths (%lu,%lu) are too large or exceed the block size %lu",
                    spindump_eventformatter_measurement_beginlength(formatter),
                    spindump_eventformatter_measurement_endlength(formatter),
                    formatter->blockSize);
    spindump_free(formatter->block);
    spindump_free(formatter);
    return(0);
  }
  
  //
  // Start the format by adding whatever prefix is needed in the output stream
  //
  
  spindump_deepdebugf("eventformatter_initialize_remote pt.4");
  if (formatter->blockSize > 0) {
    spindump_eventformatter_measurement_begin(formatter);
  }
  
  //
  // Done. Return the object.
  //
  
  spindump_deepdebugf("eventformatter_initialize_remote pt.5");
  return(formatter);
}

//
// Close the formatter, and emit any final text that may be needed
//

void
spindump_eventformatter_uninitialize(struct spindump_eventformatter* formatter) {

  //
  // Sanity checks
  //
  
  spindump_assert(formatter != 0);
  spindump_assert(formatter->file != 0 || formatter->nRemotes > 0);
  spindump_assert(formatter->analyzer != 0);

  //
  // Emit whatever post-amble is needed in the output
  //
  
  spindump_eventformatter_measurement_end(formatter);
  spindump_eventformatter_sendpooled(formatter);
  
  //
  // Unregister whatever we registered as handlers in the analyzer
  //
  
  spindump_analyze_unregisterhandler(formatter->analyzer,
                                     spindump_analyze_event_alllegal,
                                     0,
                                     spindump_eventformatter_measurement_one,
                                     formatter);
  
  //
  // Free the memory
  //
  
  spindump_free(formatter);
}

//
// Return the length of the preamble
//

static unsigned long
spindump_eventformatter_measurement_beginlength(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_beginlength_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_beginlength_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_beginlength_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return(0);
  }
}

//
// Print the begin part
//

static void
spindump_eventformatter_measurement_begin(struct spindump_eventformatter* formatter) {

  //
  // Get the begin marker. Also, as a side effect, set formatter->preambleLength.
  //
  
  spindump_deepdebugf("spindump_eventformatter_measurement_begin pt1");
  const uint8_t* data = spindump_eventformatter_measurement_beginaux(formatter,&formatter->preambleLength);
  spindump_deepdebugf("preamble = %s (length %lu)", data, formatter->preambleLength);
  
  //
  // Also, get the mid and end markers, just so that we can set
  // formatter->preambleLength and formatter->postambleLength.
  //
  
  spindump_deepdebugf("spindump_eventformatter_measurement_begin pt2");
  const uint8_t* data2 = spindump_eventformatter_measurement_endaux(formatter,&formatter->postambleLength);
  spindump_deepdebugf("postamble = %s (length %lu)", data2, formatter->postambleLength);
  spindump_deepdebugf("spindump_eventformatter_measurement_begin pt3");
  const uint8_t* data3 = spindump_eventformatter_measurement_midaux(formatter,&formatter->midambleLength);
  spindump_deepdebugf("midamble = %s (length %lu)", data3, formatter->midambleLength);
  
  //
  // Write the data to whereever it is going
  //
  
  spindump_deepdebugf("spindump_eventformatter_measurement_begin pt4");
  spindump_eventformatter_deliverdata(formatter,1,formatter->preambleLength,data);
  spindump_deepdebugf("spindump_eventformatter_measurement_begin pt5, done");
}

//
// Call the specific format function for the begin part
//

static const uint8_t*
spindump_eventformatter_measurement_beginaux(struct spindump_eventformatter* formatter,
                                             unsigned long* length) {
  *length = spindump_eventformatter_measurement_beginlength(formatter);
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_begin_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_begin_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_begin_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return((uint8_t*)"");
  }
}

//
// What is the length of the text between records?
//

static unsigned long
spindump_eventformatter_measurement_midlength(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_midlength_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_midlength_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_midlength_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return(0);
  }
}

//
// Call the format-specific function for the text between records
//

static const uint8_t*
 spindump_eventformatter_measurement_midaux(struct spindump_eventformatter* formatter,
                                           unsigned long* length) {
  spindump_deepdeepdebugf("spindump_eventformatter_measurement_midaux");
  *length = spindump_eventformatter_measurement_midlength(formatter);
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_mid_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_mid_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_mid_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return((uint8_t*)"");
  }
}

//
// What is the length of the postamble?
//

static unsigned long
spindump_eventformatter_measurement_endlength(struct spindump_eventformatter* formatter) {
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_endlength_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_endlength_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_endlength_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return(0);
  }
}

//
// Print the postamble
//

static void
spindump_eventformatter_measurement_end(struct spindump_eventformatter* formatter) {
  unsigned long length;
  const uint8_t* data = spindump_eventformatter_measurement_endaux(formatter,&length);
  spindump_eventformatter_deliverdata(formatter,1,length,data);
}

//
// Call the format-specific function for the postamble
//

static const uint8_t*
spindump_eventformatter_measurement_endaux(struct spindump_eventformatter* formatter,
                                           unsigned long* length) {
  *length = spindump_eventformatter_measurement_endlength(formatter);
  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    return(spindump_eventformatter_measurement_end_text(formatter));
  case spindump_eventformatter_outputformat_json:
    return(spindump_eventformatter_measurement_end_json(formatter));
  case spindump_eventformatter_outputformat_qlog:
    return(spindump_eventformatter_measurement_end_qlog(formatter));
  default:
    spindump_errorf("invalid output format in internal variable");
    return((uint8_t*)"");
  }
}

//
// Function that gets called whenever a new RTT data has come in for
// any connection.  This is activated when the --textual mode is on.
//

static void
spindump_eventformatter_measurement_one(struct spindump_analyze* state,
                                        void* handlerData,
                                        void** handlerConnectionData,
                                        spindump_analyze_event event,
                                        const struct timeval* timestamp,
                                        const int fromResponder,
                                        const unsigned int ipPacketLength,
                                        struct spindump_packet* packet,
                                        struct spindump_connection* connection) {

  //
  // Sanity checks
  //
  
  spindump_deepdebugf("spindump_eventformatter_measurement_one handler called for event %u", event);
  spindump_assert(state != 0);
  spindump_assert(handlerData != 0);
  spindump_assert(connection != 0);
  
  //
  // Dig up the relevant data from the handlerData pointer etc
  //

  spindump_deepdeepdebugf("point 1");
  int possibleSupress = ((state->table->periodicReportPeriod != 0) &&
                         (state->table->performingPeriodicReport == 0));
  struct spindump_eventformatter* formatter = (struct spindump_eventformatter*)handlerData;
  char session[spindump_event_sessionidmaxlength];
  spindump_connection_sessionstring(connection,session,sizeof(session));

  //
  // Check if we need to care about this event
  //
  
  spindump_deepdeepdebugf("point 2");
  if (formatter->aggregatesOnly && !spindump_connections_isaggregate(connection)) return;
  
  //
  // Construct the time stamp
  //
  
  unsigned long long timestamplonglong;
  timestamplonglong =
      ((unsigned long long)timestamp->tv_sec) * 1000 * 1000 +
      (unsigned long long)timestamp->tv_usec;
  spindump_deepdeepdebugf("event generation relative %u %llu %llu",
                          state->showRelativeTime,
                          state->firstEventTime,
                          timestamplonglong);
  if (state->showRelativeTime) {
    timestamplonglong -= state->firstEventTime;
  }
  
  //
  // Determine event type
  //
  
  spindump_deepdeepdebugf("point 4, event = %u", event);
  enum spindump_event_type eventType;
  switch (event) {

  case spindump_analyze_event_newconnection:
    spindump_deepdeepdebugf("point 5a");
    eventType = spindump_event_type_new_connection;
    break;

  case spindump_analyze_event_changeconnection:
    spindump_deepdeepdebugf("point 5b");
    eventType = spindump_event_type_change_connection;
    break;

  case spindump_analyze_event_connectiondelete:
    spindump_deepdeepdebugf("point 5c");
    eventType = spindump_event_type_connection_delete;
    break;

  case spindump_analyze_event_periodic:
    spindump_deepdeepdebugf("point 5d spindump_analyze_event_periodic");
    eventType = spindump_event_type_periodic;
    break;
    
  case spindump_analyze_event_newleftrttmeasurement:
  case spindump_analyze_event_newrightrttmeasurement:
    spindump_deepdeepdebugf("point 5d");
    if (possibleSupress) return;
    eventType = spindump_event_type_new_rtt_measurement;
    break;

  case spindump_analyze_event_newinitrespfullrttmeasurement:
    spindump_deepdeepdebugf("point 5e");
    if (possibleSupress) return;
    eventType = spindump_event_type_new_rtt_measurement;
    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    spindump_deepdeepdebugf("point 5f");
    if (possibleSupress) return;
    eventType = spindump_event_type_new_rtt_measurement;
    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_deepdeepdebugf("point 5g");
    if (possibleSupress) return;
    if (!formatter->reportSpinFlips) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_flip;
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_deepdeepdebugf("point 5h");
    if (possibleSupress) return;
    if (!formatter->reportSpinFlips) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_flip;
    break;

  case spindump_analyze_event_initiatorspinvalue:
    spindump_deepdeepdebugf("point 5i");
    if (possibleSupress) return;
    if (!formatter->reportSpins) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_value;
    break;

  case spindump_analyze_event_responderspinvalue:
    spindump_deepdeepdebugf("point 5j");
    if (possibleSupress) return;
    if (!formatter->reportSpins) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_spin_value;
    break;

  case spindump_analyze_event_newpacket:
    spindump_deepdeepdebugf("point 5x %d in eventformatter handler", formatter->reportPackets);
    if (possibleSupress) return;
    if (formatter->reportPackets) {
      eventType = spindump_event_type_packet;
      break;
    } else {
      return;
    }

  case spindump_analyze_event_initiatorecnce:
    spindump_deepdeepdebugf("point 5k");
    if (possibleSupress) return;
    eventType = spindump_event_type_ecn_congestion_event;
    break;

  case spindump_analyze_event_responderecnce:
    spindump_deepdeepdebugf("point 5l");
    if (possibleSupress) return;
    eventType = spindump_event_type_ecn_congestion_event;
    break;

  case spindump_analyze_event_initiatorrtlossmeasurement:
    spindump_deepdeepdebugf("point 5m");
    if (possibleSupress) return;
    if (!formatter->reportRtLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_rtloss_measurement;
    break;

  case spindump_analyze_event_responderrtlossmeasurement:
    spindump_deepdeepdebugf("point 5n");
    if (possibleSupress) return;
    if (!formatter->reportRtLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_rtloss_measurement;
    break;

  case spindump_analyze_event_initiatorqrlossmeasurement:
    spindump_deepdeepdebugf("point 5o");
    if (possibleSupress) return;
    if (!formatter->reportQrLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_qrloss_measurement;
    break;

  case spindump_analyze_event_responderqrlossmeasurement:
    spindump_deepdeepdebugf("point 5p");
    if (possibleSupress) return;
    if (!formatter->reportQrLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_qrloss_measurement;
    break;

  case spindump_analyze_event_initiatorqllossmeasurement:
    spindump_deepdeepdebugf("point 5q");
    if (possibleSupress) return;
    if (!formatter->reportQlLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_qlloss_measurement;
    break;

  case spindump_analyze_event_responderqllossmeasurement:
    spindump_deepdeepdebugf("point 5r");
    if (possibleSupress) return;
    if (!formatter->reportQlLoss) return;
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventType = spindump_event_type_qlloss_measurement;
    break;

  default:
    spindump_deepdeepdebugf("point 5s");
    return;

  }
  
  //
  // Create an event object
  //

  spindump_deepdeepdebugf("point 6");
  struct spindump_event eventobj;
  spindump_network initiatorAddress;
  spindump_network responderAddress;
  spindump_connections_getnetworks(connection,&initiatorAddress,&responderAddress);
  const char* notes = 0;
  char notesbuf[sizeof(eventobj.notes)];
  spindump_deepdeepdebugf("reportPackets and -Notes in eventformatter = %u %u", formatter->reportPackets, formatter->reportNotes);
  if (formatter->reportNotes) {
    spindump_connection_report_brief_notefieldval(connection,sizeof(notesbuf),notesbuf);
    notes = &notesbuf[0];
  }
  spindump_deepdeepdebugf("calling spindump_event_initialize and bandwidth calculations from spindump_eventformatter_measurement_one");
  spindump_deepdeepdebugf("going to print out debug");
  spindump_deepdeepdebugf("current and last bytes from side1 %llu %llu and from side2 %llu %llu",
                          connection->bytesFromSide1.bytesInThisPeriod,
                          connection->bytesFromSide1.bytesInLastPeriod,
                          connection->bytesFromSide2.bytesInThisPeriod,
                          connection->bytesFromSide2.bytesInLastPeriod);
  spindump_counter_64bit bw1 = spindump_bandwidth_periodbytes_to_bytespersec(&connection->bytesFromSide1);
  spindump_counter_64bit bw2 = spindump_bandwidth_periodbytes_to_bytespersec(&connection->bytesFromSide2);
  spindump_event_initialize(eventType,
                            connection->type,
                            connection->id,
                            connection->state,
                            &initiatorAddress,
                            &responderAddress,
                            session,
                            timestamplonglong,
                            connection->packetsFromSide1,
                            connection->packetsFromSide2,
                            connection->bytesFromSide1.bytes,
                            connection->bytesFromSide2.bytes,
                            bw1,
                            bw2,
                            &connection->tags,
                            notes,
                            &eventobj);
  switch (event) {

  case spindump_analyze_event_newconnection:
    break;

  case spindump_analyze_event_changeconnection:
    break;

  case spindump_analyze_event_connectiondelete:
    break;

  case spindump_analyze_event_periodic:
    eventobj.u.periodic.rttRight = connection->rightRTT.lastRTT;
    eventobj.u.periodic.avgRttRight = 0;
    eventobj.u.periodic.devRttRight = 0;
    if (formatter->averageRtts) {
      unsigned long dev;
      unsigned long filtavg = 0;
      unsigned long avg = spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT,
                                                                 formatter->filterExceptionalValuesPercentage > 0,
                                                                 formatter->filterExceptionalValuesPercentage,
                                                                 &dev,
                                                                 &filtavg);
      eventobj.u.periodic.avgRttRight = avg;
      eventobj.u.periodic.devRttRight = dev;
    }
    spindump_deepdeepdebugf("periodic eventobj.avgRttRight = %lu, averageRtts = %u",
                            eventobj.u.periodic.avgRttRight,
                            formatter->averageRtts);
    break;
    
  case spindump_analyze_event_newleftrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_frominitiator;
    eventobj.u.newRttMeasurement.rtt = connection->leftRTT.lastRTT;
    eventobj.u.newRttMeasurement.avgRtt = 0;
    eventobj.u.newRttMeasurement.devRtt = 0;
    eventobj.u.newRttMeasurement.minRtt = 0;
    if (formatter->averageRtts) {
      unsigned long dev;
      unsigned long filtavg = 0;
      unsigned long avg = spindump_rtt_calculateLastMovingAvgRTT(&connection->leftRTT,
                                                                 formatter->filterExceptionalValuesPercentage > 0,
                                                                 formatter->filterExceptionalValuesPercentage,
                                                                 &dev,
                                                                 &filtavg);
      eventobj.u.newRttMeasurement.avgRtt = avg;
      eventobj.u.newRttMeasurement.devRtt = dev;
      eventobj.u.newRttMeasurement.filtAvgRtt =
        formatter->filterExceptionalValuesPercentage > 0 ? filtavg : 0;
    }
    if (formatter->minimumRtts) {

      eventobj.u.newRttMeasurement.minRtt = connection->leftRTT.minimumRTT;

    }
    break;
    
  case spindump_analyze_event_newrightrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_bidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_fromresponder;
    eventobj.u.newRttMeasurement.rtt = connection->rightRTT.lastRTT;
    eventobj.u.newRttMeasurement.avgRtt = 0;
    eventobj.u.newRttMeasurement.devRtt = 0;
    eventobj.u.newRttMeasurement.minRtt = 0;
    eventobj.u.newRttMeasurement.filtAvgRtt = 0;
    if (formatter->averageRtts) {
      unsigned long dev;
      unsigned long filtavg = 0;
      unsigned long avg = spindump_rtt_calculateLastMovingAvgRTT(&connection->rightRTT,
                                                                 formatter->filterExceptionalValuesPercentage > 0,
                                                                 formatter->filterExceptionalValuesPercentage,
                                                                 &dev,
                                                                 &filtavg);
      eventobj.u.newRttMeasurement.avgRtt = avg;
      eventobj.u.newRttMeasurement.devRtt = dev;
      eventobj.u.newRttMeasurement.filtAvgRtt =
        formatter->filterExceptionalValuesPercentage > 0 ? filtavg : 0;
    }

    if (formatter->minimumRtts) {

      eventobj.u.newRttMeasurement.minRtt = connection->rightRTT.minimumRTT;

  }
    spindump_deepdeepdebugf("eventobj.avgRtt = %lu, averageRtts = %u",
                            eventobj.u.newRttMeasurement.avgRtt,
                            formatter->averageRtts);
    break;
    
  case spindump_analyze_event_newinitrespfullrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_frominitiator;
    eventobj.u.newRttMeasurement.rtt = connection->initToRespFullRTT.lastRTT;
    eventobj.u.newRttMeasurement.avgRtt = 0;
    eventobj.u.newRttMeasurement.devRtt = 0;
    eventobj.u.newRttMeasurement.minRtt = 0;
    eventobj.u.newRttMeasurement.filtAvgRtt = 0;
    if (formatter->averageRtts) {
      unsigned long dev;
      unsigned long filtavg = 0;
      unsigned long avg = spindump_rtt_calculateLastMovingAvgRTT(&connection->initToRespFullRTT,
                                                                 formatter->filterExceptionalValuesPercentage > 0,
                                                                 formatter->filterExceptionalValuesPercentage,
                                                                 &dev,
                                                                 &filtavg);
      eventobj.u.newRttMeasurement.avgRtt = avg;
      eventobj.u.newRttMeasurement.devRtt = dev;
      eventobj.u.newRttMeasurement.filtAvgRtt =
        formatter->filterExceptionalValuesPercentage > 0 ? filtavg : 0;
    }

    if (formatter->minimumRtts) {

      eventobj.u.newRttMeasurement.minRtt = connection->initToRespFullRTT.minimumRTT;

    }

    break;

  case spindump_analyze_event_newrespinitfullrttmeasurement:
    eventobj.u.newRttMeasurement.measurement = spindump_measurement_type_unidirectional;
    eventobj.u.newRttMeasurement.direction = spindump_direction_fromresponder;
    eventobj.u.newRttMeasurement.rtt = connection->respToInitFullRTT.lastRTT;
    eventobj.u.newRttMeasurement.avgRtt = 0;
    eventobj.u.newRttMeasurement.devRtt = 0;
    eventobj.u.newRttMeasurement.minRtt = 0;
    eventobj.u.newRttMeasurement.filtAvgRtt = 0;
    if (formatter->averageRtts) {
      unsigned long dev;
      unsigned long filtavg = 0;
      unsigned long avg = spindump_rtt_calculateLastMovingAvgRTT(&connection->respToInitFullRTT,
                                                                 formatter->filterExceptionalValuesPercentage > 0,
                                                                 formatter->filterExceptionalValuesPercentage,
                                                                 &dev,
                                                                 &filtavg);
      eventobj.u.newRttMeasurement.avgRtt = avg;
      eventobj.u.newRttMeasurement.devRtt = dev;
      eventobj.u.newRttMeasurement.filtAvgRtt =
        formatter->filterExceptionalValuesPercentage > 0 ? filtavg : 0;
    }
    if (formatter->minimumRtts) {

      eventobj.u.newRttMeasurement.minRtt = connection->respToInitFullRTT.minimumRTT;

    }
    break;

  case spindump_analyze_event_initiatorspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinFlip.direction = spindump_direction_frominitiator;
    eventobj.u.spinFlip.spin0to1 = connection->u.quic.spinFromPeer1to2.lastSpin;
    break;

  case spindump_analyze_event_responderspinflip:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinFlip.direction = spindump_direction_fromresponder;
    eventobj.u.spinFlip.spin0to1 = connection->u.quic.spinFromPeer2to1.lastSpin;
    break;
    
  case spindump_analyze_event_initiatorspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinValue.direction = spindump_direction_frominitiator;
    eventobj.u.spinValue.value = (uint8_t)connection->u.quic.spinFromPeer1to2.lastSpin;
    break;

  case spindump_analyze_event_responderspinvalue:
    spindump_assert(connection->type == spindump_connection_transport_quic);
    eventobj.u.spinValue.direction = spindump_direction_fromresponder;
    eventobj.u.spinValue.value = (uint8_t)connection->u.quic.spinFromPeer2to1.lastSpin;
    break;

  case spindump_analyze_event_initiatorecnce:
    eventobj.u.ecnCongestionEvent.direction = spindump_direction_frominitiator;
    eventobj.u.ecnCongestionEvent.ecn0 = connection->ect0FromInitiator + connection->ect0FromResponder;
    eventobj.u.ecnCongestionEvent.ecn1 = connection->ect1FromInitiator + connection->ect1FromResponder;
    eventobj.u.ecnCongestionEvent.ce = connection->ceFromInitiator + connection->ceFromResponder;
    break;

  case spindump_analyze_event_responderecnce:
    eventobj.u.ecnCongestionEvent.direction = spindump_direction_fromresponder;
    break;

  case spindump_analyze_event_initiatorrtlossmeasurement:
    eventobj.u.rtlossMeasurement.direction = spindump_direction_frominitiator;
    sprintf(eventobj.u.rtlossMeasurement.avgLoss, "%.3f", connection->rtLossesFrom1to2.averageLossRate * 100);
    sprintf(eventobj.u.rtlossMeasurement.totLoss, "%.3f", connection->rtLossesFrom1to2.totalLossRate * 100);
    break;

  case spindump_analyze_event_responderrtlossmeasurement:
    eventobj.u.rtlossMeasurement.direction = spindump_direction_fromresponder;
    sprintf(eventobj.u.rtlossMeasurement.avgLoss, "%.3f", connection->rtLossesFrom2to1.averageLossRate * 100);
    sprintf(eventobj.u.rtlossMeasurement.totLoss, "%.3f", connection->rtLossesFrom2to1.totalLossRate * 100);
    break;

  case spindump_analyze_event_initiatorqrlossmeasurement:
    eventobj.u.qrlossMeasurement.direction = spindump_direction_frominitiator;
    sprintf(eventobj.u.qrlossMeasurement.avgLoss, "%.3f", connection->u.quic.qrLossesFrom1to2.averageLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.totLoss, "%.3f", connection->u.quic.qrLossesFrom1to2.totalLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.avgRefLoss, "%.3f", connection->u.quic.qrLossesFrom1to2.averageRefLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.totRefLoss, "%.3f", connection->u.quic.qrLossesFrom1to2.totalRefLossRate * 100);
    break;

  case spindump_analyze_event_responderqrlossmeasurement:
    eventobj.u.qrlossMeasurement.direction = spindump_direction_fromresponder;
    sprintf(eventobj.u.qrlossMeasurement.avgLoss, "%.3f", connection->u.quic.qrLossesFrom2to1.averageLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.totLoss, "%.3f", connection->u.quic.qrLossesFrom2to1.totalLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.avgRefLoss, "%.3f", connection->u.quic.qrLossesFrom2to1.averageRefLossRate * 100);
    sprintf(eventobj.u.qrlossMeasurement.totRefLoss, "%.3f", connection->u.quic.qrLossesFrom2to1.totalRefLossRate * 100);
    break;

  case spindump_analyze_event_initiatorqllossmeasurement:
    eventobj.u.qllossMeasurement.direction = spindump_direction_frominitiator;
    sprintf(eventobj.u.qllossMeasurement.qLoss, "%.3f", connection->qLossesFrom1to2 * 100);
    sprintf(eventobj.u.qllossMeasurement.lLoss, "%.3f", connection->rLossesFrom1to2 * 100);
    break;
  
  case spindump_analyze_event_responderqllossmeasurement:
    eventobj.u.qllossMeasurement.direction = spindump_direction_fromresponder;
    sprintf(eventobj.u.qllossMeasurement.qLoss, "%.3f", connection->qLossesFrom2to1 * 100);
    sprintf(eventobj.u.qllossMeasurement.lLoss, "%.3f", connection->rLossesFrom2to1 * 100);
    break;

  case spindump_analyze_event_newpacket:
    eventobj.u.packet.direction = fromResponder ? spindump_direction_fromresponder : spindump_direction_frominitiator;
    eventobj.u.packet.length = ipPacketLength;
    break;
    
  default:
    spindump_deepdeepdebugf("point x");
    return;

  }

  //
  // Based on the format type, provide different kinds of output
  //

  switch (formatter->format) {
  case spindump_eventformatter_outputformat_text:
    spindump_eventformatter_measurement_one_text(formatter,event,&eventobj,connection);
    break;
  case spindump_eventformatter_outputformat_json:
    spindump_eventformatter_measurement_one_json(formatter,event,&eventobj,connection);
    break;
  case spindump_eventformatter_outputformat_qlog:
    spindump_eventformatter_measurement_one_qlog(formatter,event,&eventobj,connection);
    break;
  default:
    spindump_errorf("invalid output format in internal variable");
    exit(1);
  }
}

//
// Determine Internet media type based on the format
//

static const char*
spindump_eventformatter_mediatype(enum spindump_eventformatter_outputformat format) {
  switch (format) {
  case spindump_eventformatter_outputformat_text:
    return("application/text");
  case spindump_eventformatter_outputformat_json:
    return("application/json");
  case spindump_eventformatter_outputformat_qlog:
    return("application/json");
  default:
    spindump_errorf("invalid format");
    return("application/text");
  }
}

//
// If a number of updates have been pooled to a server, send them now.
//

void
spindump_eventformatter_sendpooled(struct spindump_eventformatter* formatter) {
  spindump_assert(formatter != 0);
  if (formatter->bytesInBlock > formatter->preambleLength) {
    spindump_deepdebugf("sendpooled bytes %lu", formatter->bytesInBlock);
    unsigned long postambleLength;
    const uint8_t* postamble = spindump_eventformatter_measurement_endaux(formatter,&postambleLength);
    memcpy(formatter->block + formatter->bytesInBlock,postamble,postambleLength);
    formatter->bytesInBlock += postambleLength;
    spindump_eventformatter_deliverdata_remoteblock(formatter,
                                                    formatter->bytesInBlock,
                                                    formatter->block);
    formatter->bytesInBlock = 0;
    spindump_eventformatter_measurement_begin(formatter);
  }
}

//
// Internal function that is called by the different format
// formatters, to deliver a bunch of bytes (e.g., a JSON string)
// towards the output. Depending on where the output needs to go, it
// could either be printed or queued up for storage to be later
// delivered via HTTP to a collector point.
//

void
spindump_eventformatter_deliverdata(struct spindump_eventformatter* formatter,
                                    int amble,
                                    unsigned long length,
                                    const uint8_t* data) {
  spindump_deepdeepdebugf("eventformatter: spindump_eventformatter_deliverdata %u bytes\n%s",
                          length, data);
  if (formatter->file != 0) {
    
    //
    // Check first if there's a need to add a "midamble" between records. 
    //

    spindump_deepdebugf("eventformatter: deliverdata midamble check length %lu postambleLength %lu entries %u",
                        length, formatter->postambleLength, formatter->nEntries);
    if (!amble) { // was: (length > spindump_eventformatter_maxamble) {
      if (formatter->nEntries > 0) {
        spindump_deepdebugf("spindump_eventformatter_deliverdata pt2");
        const uint8_t* mid = spindump_eventformatter_measurement_midaux(formatter,&formatter->midambleLength);
        fwrite(mid,formatter->midambleLength,1,formatter->file);
        spindump_deepdebugf("eventformatter: wrote midamble of %u bytes: %s", formatter->midambleLength, mid);
      }
      formatter->nEntries++;
    }

    //
    // Write the actual entry out. We're just outputting data to
    // stdout; print it out
    //
    
    fwrite(data,length,1,formatter->file);
    spindump_deepdebugf("eventformatter: wrote data %s", data);
    fflush(formatter->file);
    
  } else if (formatter->nRemotes > 0) {
    
    //
    // We need to send data to remote collector point(s). If blockSize
    // is zero, then we simply send right away.
    //

    if (formatter->blockSize == 0) {
      spindump_eventformatter_deliverdata_remoteblock(formatter,
                                                      length,
                                                      data);
      
    } else {
      
      //
      // Otherwise, keep pooling data in a buffer until block size is filled
      //
      
      if (formatter->bytesInBlock + spindump_eventformatter_maxmidamble + length + spindump_eventformatter_maxpostamble <
          formatter->blockSize) {
        
        //
        // All fits in and still some space
        //

        spindump_deepdebugf("eventformatter: (1) checking to see if need to insert the midamble (%lu bytes vs. %lu preamble length",
                            formatter->bytesInBlock, formatter->preambleLength);
        if (formatter->bytesInBlock > formatter->preambleLength) {
          size_t midlength;
          spindump_deepdebugf("spindump_eventformatter_deliverdata pt3");
          const uint8_t* mid = spindump_eventformatter_measurement_midaux(formatter,&midlength);
          spindump_deepdebugf("eventformatter: (1) adding midamble %s of %lu bytes", mid, midlength);
          memcpy(formatter->block + formatter->bytesInBlock,mid,midlength);
          formatter->bytesInBlock += midlength;
        }
        memcpy(formatter->block + formatter->bytesInBlock,data,length);
        formatter->bytesInBlock += length;
        
      } else if (formatter->bytesInBlock + spindump_eventformatter_maxmidamble + length + spindump_eventformatter_maxpostamble ==
                 formatter->blockSize) {
        
        //
        // All fits in but exactly
        //
        
        spindump_deepdebugf("eventformatter: (2) checking to see if need to insert the midamble (%lu bytes vs. %lu preamble length",
                            formatter->bytesInBlock, formatter->preambleLength);
        if (formatter->bytesInBlock > formatter->preambleLength) {
          size_t midlength;
          spindump_deepdebugf("spindump_eventformatter_deliverdata pt4");
          const uint8_t* mid = spindump_eventformatter_measurement_midaux(formatter,&midlength);
          spindump_deepdebugf("(2) adding midamble %s of %lu bytes", mid, midlength);
          memcpy(formatter->block + formatter->bytesInBlock,mid,midlength);
          formatter->bytesInBlock += midlength;
        }
        memcpy(formatter->block + formatter->bytesInBlock,data,length);
        formatter->bytesInBlock += length;
        unsigned long postambleLength;
        const uint8_t* postamble = spindump_eventformatter_measurement_endaux(formatter,&postambleLength);
        memcpy(formatter->block + formatter->bytesInBlock,postamble,postambleLength);
        formatter->bytesInBlock += postambleLength;
        spindump_eventformatter_deliverdata_remoteblock(formatter,
                                                        formatter->bytesInBlock,
                                                        formatter->block);
        formatter->bytesInBlock = 0;
        spindump_eventformatter_measurement_begin(formatter);
        
      } else {

        //
        // Latest entry does not fit in, send the current block and
        // then put this entry to the buffer
        //
        
        unsigned long postambleLength;
        const uint8_t* postamble = spindump_eventformatter_measurement_endaux(formatter,&postambleLength);
        memcpy(formatter->block + formatter->bytesInBlock,postamble,postambleLength);
        formatter->bytesInBlock += postambleLength;
        spindump_eventformatter_deliverdata_remoteblock(formatter,
                                                        formatter->bytesInBlock,
                                                        formatter->block);
        formatter->bytesInBlock = 0;
        spindump_eventformatter_measurement_begin(formatter);
        memcpy(formatter->block + formatter->bytesInBlock,data,length);
        formatter->bytesInBlock += length;
        
      }
    }
    
  } else {
    
    spindump_errorf("no event destination specified");
    
  }
}

//
// Deliver one block of data to the remote collector point(s)
//

static void
spindump_eventformatter_deliverdata_remoteblock(struct spindump_eventformatter* formatter,
                                                unsigned long length,
                                                const uint8_t* data) {
  for (unsigned int i = 0; i < formatter->nRemotes; i++) {
    struct spindump_remote_client* client = formatter->remotes[i];
    spindump_assert(client != 0);
    const char* mediaType = spindump_eventformatter_mediatype(formatter->format);
    spindump_remote_client_update_event(client,mediaType,length,data);
  }
}
