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

/* Basic implementation of an HTTP 0.9 responder */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* We want a highly portable pseudorandom generator. We don't really care 
 * about the randomness, because this is a silly app, so we pick something really
 * simple and easy to program. But we don't use rand() because visual studio 
 * would call it unsafe, or other packages because we don't want to be bothered
 * with portability issues. The constant here are those of Knuth's MMIX */
static uint64_t http09_rand(uint64_t seed)
{
    const uint64_t a = 6364136223846793005ull;
    const uint64_t c = 1442695040888963407ull;
    uint64_t x = seed * a + c;

    return x;
}

/*
 * The text in the OK text will be used as the basis for generating random text.
 * For now, the only things that matter is character frequency.
 */
static char const* http09_ok_text = "The quick brown fox jumps over the lazy dog. 0123456789.,!?";

static uint64_t http09_random_chars(uint64_t seed, uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 0;
    uint8_t rchar = 0;
    size_t text_mod = strlen(http09_ok_text);
    uint64_t text_index = 0;

    while (byte_index < bytes_max) {
        seed = http09_rand(seed);
        text_index = seed % text_mod;

        rchar = (uint8_t)http09_ok_text[text_index];
        bytes[byte_index++] = rchar;

        if ((byte_index % 72) == 0 && byte_index < bytes_max) {
            bytes[byte_index++] = (uint8_t)'\n';
        }
    }

    return seed;
}

static int http09_random_txt(size_t doc_length, uint8_t* response, size_t response_max,
    size_t* response_length)
{
    uint64_t seed = 0x1234567890ull ^ doc_length;

    if (doc_length > response_max) {
        doc_length = response_max;
    }

    (void)http09_random_chars(seed, response, doc_length);

    *response_length = doc_length;

    return 0;
}

#define http09_head1 "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>"
#define http09_head2  "</TITLE>\r\n</HEAD><BODY>\r\n"
#define http09_final  "</BODY></HTML>\r\n"

#define http09_index_title  "PicoQuic HTTP 0.9 service"

#define http09_index_1  "<h1>Simple HTTP 0.9 Responder</h1>\r\n"
#define http09_index_2  "<p>GET /, and GET index.html returns this text</p>\r\n"
#define http09_index_3  "<p>Get /doc-NNNNN.html returns html document of length NNNNN bytes(decimal)</p>\r\n"
#define http09_index_4  "<p>Get /doc-NNNNN also returns html document of length NNNNN bytes(decimal)</p>\r\n"
#define http09_index_5  "<p>Get /doc-NNNNN.txt returns txt document of length NNNNN bytes(decimal)</p>\r\n"
#define http09_index_6  "<p>Get /NNNNN returns html document of length NNNNN bytes(decimal)</p>\r\n"
#define http09_index_7  "<p>Any other command will result in an error, and an empty response.</p>\r\n"
#define http09_index_8  "<h1>Enjoy!</h1>\r\n"

static size_t http09_paragraph_min(size_t tag_length)
{
    /* account for <tag></tag>\r\n */
    return (2 * tag_length + 7);
}

static uint64_t http09_random_paragraph(uint64_t seed, size_t text_length,
    char const* tag, size_t tag_length, uint8_t* bytes)
{
    size_t byte_index = 0;
    /* Copy opening tag */
    bytes[byte_index++] = '<';
    memcpy(bytes + byte_index, tag, tag_length);
    byte_index += tag_length;
    bytes[byte_index++] = '>';

    /* generate the random text */
    seed = http09_random_chars(seed, bytes + byte_index, text_length);
    byte_index += text_length;

    /* Copy final tag */
    bytes[byte_index++] = '<';
    bytes[byte_index++] = '/';
    memcpy(bytes + byte_index, tag, tag_length);
    byte_index += tag_length;
    bytes[byte_index++] = '>';
    bytes[byte_index++] = '\r';
    bytes[byte_index++] = '\n';

    return seed;
}

static int http09_random_html(size_t doc_length, uint8_t* bytes, size_t bytes_max,
    size_t* response_length)
{
    uint64_t seed = 0xDEADBEEFull ^ doc_length;
    size_t min_length = strlen(http09_head1) + 16 + strlen(http09_head2) + 16 + strlen(http09_final);
    size_t body_length = 0;
    size_t byte_index = 0;

    if (bytes_max < min_length) {
        *response_length = 0;
        return -1;
    }

    if (doc_length > bytes_max) {
        doc_length = bytes_max;
    }

    /* Copy the header 1 */
    memcpy(bytes + byte_index, http09_head1, strlen(http09_head1));
    byte_index += strlen(http09_head1);

    /* Generate the title */
    seed = http09_random_chars(seed, bytes + byte_index, 16);
    byte_index += 16;

    /* Copy the header 2 */
    memcpy(bytes + byte_index, http09_head2, strlen(http09_head2));
    byte_index += strlen(http09_head2);

    body_length = doc_length - byte_index - strlen(http09_final);

    /* Generate a series of sections and paragraphs */
    while (body_length > 0) {
        /* Compute the number of paragraphs */
        size_t nb_paragraphs;
        size_t title_length;
        size_t para_length;

        seed = http09_rand(seed);

        title_length = (size_t)(seed & 15) + 5;
        nb_paragraphs = ((seed >> 4) & 7) + 1;

        if (body_length > http09_paragraph_min(2)) {
            body_length -= http09_paragraph_min(2);

            if (title_length > body_length) {
                title_length = body_length;
            }
            body_length -= title_length;
            /* Generate an H1 header. */
            seed = http09_random_paragraph(seed, title_length, "h1", 2,
                bytes + byte_index);
            byte_index += http09_paragraph_min(2) + title_length;
        }

        while (nb_paragraphs > 0 && body_length > 0) {
            seed = http09_rand(seed);
            para_length = (size_t)(seed & 511) + 13;

            if (body_length > http09_paragraph_min(1)) {
                body_length -= http09_paragraph_min(1);

                if (para_length > body_length) {
                    para_length = body_length;
                }
                body_length -= para_length;
                /* Generate an H1 header. */
                seed = http09_random_paragraph(seed, para_length, "p", 1,
                    bytes + byte_index);
                byte_index += http09_paragraph_min(1) + para_length;
            } else {
                while (body_length > 0) {
                    bytes[byte_index++] = ' ';
                    body_length--;
                }
            }

            nb_paragraphs--;
        }
    }

    /* Copy the final tags */
    memcpy(bytes + byte_index, http09_final, strlen(http09_final));
    byte_index += strlen(http09_final);

    *response_length = byte_index;

    return 0;
}

static int http09_index_html(uint8_t* bytes, size_t bytes_max,
    size_t* response_length)
{
    int ret = 0;
    char const* index_text[] = { http09_head1,
        http09_index_title, http09_head2,
        http09_index_1, http09_index_2, http09_index_3,
        http09_index_4, http09_index_5, http09_index_6,
        http09_index_7, http09_index_8, http09_final };
    size_t nb_index_blocks = sizeof(index_text) / sizeof(char* const);
    size_t byte_index = 0;

    for (size_t i = 0; i < nb_index_blocks; i++) {
        size_t l = strlen(index_text[i]);

        if (byte_index + l <= bytes_max) {
            memcpy(bytes + byte_index, index_text[i], l);
            byte_index += l;
        } else {
            ret = -1;
            break;
        }
    }

    if (ret == 0) {
        *response_length = byte_index;
    } else {
        *response_length = 0;
    }

    return ret;
}

static int http09_compare_name(uint8_t* command, size_t length, size_t byte_index, char* name)
{
    int ret = -1;
    for (size_t i = 0;; i++, byte_index++) {
        if ((uint8_t)name[i] == 0) {
            if (byte_index == length) {
                ret = 0;
            }
            break;
        } else if (byte_index >= length) {
            break;
        } else {
            uint8_t c = (uint8_t)name[i];

            if (c != command[byte_index]) {
                if (c >= 'a' && c <= 'z') {
                    c -= 'a' - 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c += 'a' - 'A';
                }
                if (c != command[byte_index]) {
                    break;
                }
            }
        }
    }

    return ret;
}

int http0dot9_get(uint8_t* command, size_t command_length,
    uint8_t* response, size_t response_max, size_t* response_length)
{
    int ret = 0;
    size_t byte_index = 3;
    size_t doc_length = 0;

    *response_length = 0;
    /* Strip white spaces at the end of the command */
    while (command_length > 0) {
        int c = command[command_length - 1];

        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            command_length--;
        } else {
            break;
        }
    }

    /* Check whether someone added an HTTP/0.9 tag at the end of the command */
    if (command_length > 8 && command[command_length - 1] == '9' && command[command_length - 2] == '.' && command[command_length - 3] == '0' && command[command_length - 4] == '/' && (command[command_length - 5] == 'p' || command[command_length - 5] == 'P') && (command[command_length - 6] == 't' || command[command_length - 6] == 'T') && (command[command_length - 7] == 't' || command[command_length - 7] == 'T') && (command[command_length - 8] == 'h' || command[command_length - 8] == 'H')) {
        command_length -= 8;

        while (command_length > 0 && (command[command_length - 1] == ' ' || command[command_length - 1] == '\t')) {
            command_length--;
        }
    }

    /* Parse the input. It should be "get <docname> */
    if (command_length < 4 || (command[0] != 'G' && command[0] != 'g') || (command[1] != 'E' && command[1] != 'e') || (command[2] != 'T' && command[2] != 't')) {
        ret = -1;
    } else {
        /* Skip at list one space */
        while (command_length > byte_index && (command[byte_index] == ' ' || command[byte_index] == '\t')) {
            byte_index++;
        }

        if (byte_index == 3 || byte_index >= command_length) {
            ret = -1;
        }
    }

    /* if the input is in incorrect form, return 0 length error message */
    if (ret == -1) {
        *response_length = 0;
    }
    /* if the doc name  is a known value, return it */
    else if (http09_compare_name(command, command_length, byte_index, "/") == 0) {
        ret = http09_index_html(response, response_max, response_length);
    } else {
        if (command[byte_index] == '/') {
            byte_index++;
        }

        if (http09_compare_name(command, command_length, byte_index, "index.html") == 0) {
            ret = http09_index_html(response, response_max, response_length);
        } else {
            /* if the doc name is of form doc-NNNNNNNN.html,
             * generate the html text, stopping at response_length_max if the number is too long.
             */
            if (command_length < byte_index + 9 || (command[byte_index + 0] != 'D' && command[byte_index + 0] != 'd') || (command[byte_index + 1] != 'O' && command[byte_index + 1] != 'o') || (command[byte_index + 2] != 'C' && command[byte_index + 2] != 'c') || (command[byte_index + 3] != '-')) {
                /* find whether the name is of form 999999 */
                while (byte_index < command_length && command[byte_index] >= '0' && command[byte_index] <= '9') {
                    doc_length *= 10;
                    doc_length += command[byte_index] - '0';
                    byte_index++;
                }

                if (doc_length > 0)
                {
                    ret = http09_random_html(doc_length, response, response_max, response_length);
                } else {
                    ret = -1;
                }

            } else {
                byte_index += 4;

                while (byte_index < command_length && command[byte_index] >= '0' && command[byte_index] <= '9') {
                    doc_length *= 10;
                    doc_length += command[byte_index] - '0';
                    byte_index++;
                }

                if (doc_length == 0 || http09_compare_name(command, command_length, byte_index, ".html") == 0) {
                    /* HTML by default */
                    ret = http09_random_html(doc_length, response, response_max, response_length);
                } else if (http09_compare_name(command, command_length, byte_index, ".txt") == 0) {
                    /* Random text */
                    ret = http09_random_txt(doc_length, response, response_max, response_length);
                } else {
                    ret = -1;
                }
            }
        }
    }

    return ret;
}
