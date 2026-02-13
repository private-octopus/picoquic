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
#include "picoquic.h"
#include "picoquic_newreno.h"
#include "picoquic_cubic.h"
#include "picoquic_bbr.h"
#include "picoquic_bbr1.h"
#include "picoquic_fastcc.h"
#include "picoquic_prague.h"
#include "c4.h"


/* Register a complete list of congestion control algorithms, which
* can then be used by calls to picoquic_get_congestion_algorithm()
* and picoquic_create_and_configure(). 
 */

picoquic_congestion_algorithm_t const* getter_test_cc_algo_list[8] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

void picoquic_register_all_congestion_control_algorithms()
{
    getter_test_cc_algo_list[0] = picoquic_newreno_algorithm;
    getter_test_cc_algo_list[1] = picoquic_cubic_algorithm;
    getter_test_cc_algo_list[2] = picoquic_dcubic_algorithm;
    getter_test_cc_algo_list[3] = picoquic_fastcc_algorithm;
    getter_test_cc_algo_list[4] = picoquic_bbr_algorithm;
    getter_test_cc_algo_list[5] = picoquic_prague_algorithm;
    getter_test_cc_algo_list[6] = picoquic_bbr1_algorithm;
    getter_test_cc_algo_list[7] = c4_algorithm;
    picoquic_register_congestion_control_algorithms(getter_test_cc_algo_list, 8);
}