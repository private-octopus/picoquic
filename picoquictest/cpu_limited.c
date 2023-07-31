/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"

/* Add a series of tests to study the behavior of cpu-limited clients.
* This requires simulating clients that have cpu limitations, such
* as only being able to proceed a set number of messages per second.
* 
* The main effort is to modify the simulator to keep track of the
* "software load" of a node. The simulator interacts with the code
* through two APIs: prepare a packet to send; and, receive a packet.
* We assume that each of these calls will take some time, because
* it includes CPU processing. The simulation needs to maintain a
* "node readiness" clock, so that the node only becomes available
* some time after performing an action. Then, we do the following:
* 
* - On the "prepare packet" side, only consider the client ready
*   if time is large than the next ready time and also larger
*   than the next clock readiness time. Increase the next ready
*   time if a packet is successfully processed (but not if the
*   prepare packet call returns "no action").
* 
* - On the "receive packet" side, only accept a packet if the
*   arrival time is after the the next ready time. If it is not,
*   queue the packet in an "arrival queue", and drop it if the
*   arrival queue is over some limit. Increase the next ready
*   time after the packet is processed
*
* We test this configuration with a couple of scenarios.
*/

int limited_endpoint_test()
{
    return -1;
}
