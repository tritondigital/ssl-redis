/* Select()-based ae.c module
 * Copyright (C) 2009-2010 Salvatore Sanfilippo - antirez@gmail.com
 * Released under the BSD license. See the COPYING file for more info. */

#include <string.h>

typedef struct aeApiState {
    fd_set rfds, wfds;
    /* We need to have a copy of the fd sets as it's not safe to reuse
     * FD sets after select(). */
    fd_set _rfds, _wfds;
} aeApiState;

static int aeApiCreate(aeEventLoop *eventLoop) {
    aeApiState *state = zmalloc(sizeof(aeApiState));

    if (!state) return -1;
    FD_ZERO(&state->rfds);
    FD_ZERO(&state->wfds);
    eventLoop->apidata = state;
    return 0;
}

static void aeApiFree(aeEventLoop *eventLoop) {
    zfree(eventLoop->apidata);
}

static int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_SET(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_SET(fd,&state->wfds);
    return 0;
}

static void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_CLR(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_CLR(fd,&state->wfds);
}

static int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) {
    aeApiState *state = eventLoop->apidata;
    int retval, j, numevents = 0;

    memcpy(&state->_rfds,&state->rfds,sizeof(fd_set));
    memcpy(&state->_wfds,&state->wfds,sizeof(fd_set));

    //
    // TODO:
    //  Check the existing SSL connections to see if they have any pending bytes (in the SSL buffers) and process them
    // before doing a regular select. If we don't we could hang.
    //
    int pendingSSL = 0;
    for(j = 0; j <= eventLoop->maxfd; j++){
      aeFileEvent *fe = &eventLoop->events[j];
      if( fe->clientDataType == 1 ) {
        redisClient *cli = (redisClient*)fe->clientData;
        if( cli->ssl.ssl ) {
          if( SSL_pending( cli->ssl.ssl ) > 0 ) {
          
            if (fe->mask == AE_NONE) continue;

            int mask = 0;

            if (fe->mask & AE_READABLE) {
              ++pendingSSL;
              mask |= AE_READABLE;

              eventLoop->fired[numevents].fd = j;
              eventLoop->fired[numevents].mask = mask;
              numevents++;
            }

          }
        }
      }
    }

    //
    // Only select if there are no pending SSL reads... Else we'll permanently block.
    //
    if( pendingSSL == 0 ) {
      retval = select(eventLoop->maxfd+1,
                &state->_rfds,&state->_wfds,NULL,tvp);
    }

    //
    // If we have any sockets that need to be read (other than the SSL ones) then do them
    //
    if (retval > 0) {
        for (j = 0; j <= eventLoop->maxfd; j++) {
            int mask = 0;
            aeFileEvent *fe = &eventLoop->events[j];

            if (fe->mask == AE_NONE) continue;
            if (fe->mask & AE_READABLE && FD_ISSET(j,&state->_rfds)) {
                mask |= AE_READABLE;
            }
            if (fe->mask & AE_WRITABLE && FD_ISSET(j,&state->_wfds)) {
                mask |= AE_WRITABLE;
            }
            eventLoop->fired[numevents].fd = j;
            eventLoop->fired[numevents].mask = mask;
            numevents++;
        }
    }

    return numevents;
}

static char *aeApiName(void) {
    return "select";
}
