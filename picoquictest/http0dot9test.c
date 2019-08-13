#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

int http0dot9_get(uint8_t* command, size_t command_length,
    uint8_t* response, size_t response_max, size_t* response_length);

int http0dot9_test_one(char const* command, int expected_ret, size_t expected_length,
    char const* fileName)
{
    int ret = 0;
    int c_ret = 0;
    const size_t big_size = 1 << 20;
    uint8_t* big_buffer = (uint8_t*)malloc(big_size);
    size_t content_length = 0;

    if (big_buffer == NULL) {
        ret = -1;
    } else {
        c_ret = http0dot9_get((uint8_t*)command, strlen(command), big_buffer, big_size, &content_length);

        if (c_ret != expected_ret || content_length != expected_length) {
            ret = -1;
        } else if (c_ret == 0 && fileName != 0) {
            FILE* F = NULL;

            if ((F = picoquic_file_open(fileName, "w")) == NULL) {
                DBG_PRINTF("Cannot open file %s\n", fileName);
                ret = -1;
            }
            else {
                (void)fwrite(big_buffer, 1, content_length, F);

                F = picoquic_file_close(F);
            }
        }
        free(big_buffer);
    }

    return ret;
}

int http0dot9_test()
{
    int ret = 0;
    const size_t index_html_size = 633;
    
    ret = http0dot9_test_one("get /", 0, index_html_size, "http09_index.html");

    if (ret == 0) {
        ret = http0dot9_test_one("get /\r\n", 0, index_html_size, "http09_index2.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get / HTTP/0.9", 0, index_html_size, "http09_index.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get / HTTP/0.9\r\n", 0, index_html_size, "http09_index.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get index.html", 0, index_html_size, "http09_index3.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get doc-12345.html", 0, 12345, "http09_12345.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get /12345", 0, 12345, "http09_12345.html");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get doc-1234.txt", 0, 1234, "http09_1234.txt");
    }

    if (ret == 0) {
        ret = http0dot9_test_one("post 12345.html", -1, 0, NULL);
    }

    if (ret == 0) {
        ret = http0dot9_test_one("get nosuch.html", -1, 0, NULL);
    }

    return ret;
}
