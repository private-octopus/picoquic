/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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

/* The "video" adjunct to the sample application provides an example of
* a video server and a video client. Calling that "video" is a bit optimistic.
* A real video server would need to interface with cameras, or maybe
* parse files of recorded videos. Someone may want to contribute that
* code eventually, but for now we just create blank "video frames",
* which really are just binary blobs filled with pseudo content.
* We mimic the output of a video codec: one big I frame, followed
* by a series of smaller P frames. Each frame has video number,
* a group number that is incremented
* when we create an I frame, a frame number, starting at zero for the
* I frame and incremented for each P frame, and a production time.
*
* We expect to carry these frames in a series of unidirectional streams,
* with all frames from a given group in the same stream.
*
* The client will request a video stream via a client command, in a
* bidir stream. This will cause the server to start a video producing
* thread, and then push a series of unidir stream. The production will
* cease when the client cloases the bidir stream.
* The client command may provide indications such as FPS, size of
* I frame, size of P frame, and number of frames per group.
*
* The client will receive the bidir streams and pass them to a "player",
* which will simulate video processing. (Maybe write a line of text
* with one char per frame?) Frames can only be "displayed" if all
* previous frames have been received. We will measure the playback
* time, collect statistics, etc.
*
* The key part of the sample is the communication of frames between
* the producer and the stack on one hand, the stack and the consumer
* thread on the other hand.
*
* On the sender side, we rely on the `add block to stream` API. The
* frames are added to a circular buffer, with a read pointer for the
* stack and a write pointer for the producer. We allocate a
* buffer size (CIRCULAR_BUFFER_SIZE), and assume that the read pointer
* advances fast enough to allow for real time. The read pointer
* is processed within one of the picoquic callbacks: map the logical stream
* to an actual stream number, then call the add block to stream API.
* If needed, add a "FIN" mark to the stream, or reset the stream.
* 
* We use a similar circular buffer at the client for the communication
* the stack and the client thread, with a bit of difference. The
* stack will accumulate bytes in the "write" buffer, and progress the
* pointer when it is full. After writing, it will call the
* "wakeup" routine for the client.
*/

#define CIRCULAR_BUFFER_SIZE 16

typedef struct st_circular_buffer_entry_t {
    uint64_t logical_stream;
    uin8_t* buffer;
    size_t length;
    int is_fin;
    int is_reset;
} circular_buffer_entry_t;


typedef struct st_circular_buffer_t {
    int write_point;
    int read_point;
    circular_buffer_entry_t[CIRCULAR_BUFFER_SIZE];
};
