/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* The "sample" project builds a simple file transfer program that can be 
 * instantiated in client or server mode. The programe can be instantiated
 * as either:
 *    pqsample client server_name[:port] folder *queried_file
 * or:
 *    pqsample server port folder cert_file private_key_file
 *
 * The client opens a quic connection to the server, and then fetches 
 * the listed files. The client opens one bidir client stream for each
 * file, writes the requested file name in the stream data, and then
 * marks the stream as finished. The server reads the file name, and
 * if the named file is present in the server's folder, sends the file
 * content on the same stream, marking the fin of the stream when all
 * bytes are sent. If the file is not available, the server resets the
 * stream. If the client receives the file, it writes its content in the
 * client's folder.
 *
 * Server or client close the connection if it remains inactive for
 * more than 10 seconds.
 */

int main(int argc, char** argv)
{
}