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

#include "CppUnitTest.h"
#include "picoquictest/picoquictest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PerfAndStressTest
{
	TEST_CLASS(PerfAndStressTest)
	{
	public:
        TEST_CLASS_INITIALIZE(setup) {
            // avoid large debug spew that slows down the console.
            debug_printf_suspend();
        }

        TEST_METHOD(satellite_basic)
        {
            int ret = satellite_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(satellite_loss)
        {
            int ret = satellite_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(satellite_jitter)
        {
            int ret = satellite_jitter_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(satellite_medium)
        {
            int ret = satellite_medium_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(satellite_small)
        {
            int ret = satellite_small_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(satellite_small_up)
        {
            int ret = satellite_small_up_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stress)
        {
            int ret = stress_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(http_stress) {
            int ret = http_stress_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(http_corrupt) {
            int ret = http_corrupt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(fuzz)
        {
            int ret = fuzz_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(fuzz_initial)
        {
            int ret = fuzz_initial_test();

            Assert::AreEqual(ret, 0);
        }
	};
}
