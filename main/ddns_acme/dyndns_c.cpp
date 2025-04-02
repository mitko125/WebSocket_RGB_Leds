/*
 * This is the C language interface to the (originally C++) acmeclient library,
 * a client for Let's Encrypt (https://letsencrypt.org).
 *
 * Copyright (c) 2024 Danny Backx
 *
 * License (MIT license):
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

#include "Dyndns.h"

static Dyndns *dd = 0;

static void _dyndns_init(enum dyndns_provider dp)
{
    dd = new Dyndns(dp);
}

static void _dyndns_set_hostname(const char *hn)
{
    dd->setHostname(hn);
}

static void _dyndns_set_auth(const char *auth)
{
    dd->setAuth(auth);
}

static bool _dyndns_update()
{
    return dd->update();
}

extern "C" {
    void dyndns_init(enum dyndns_provider dp)
    {
        _dyndns_init(dp);
    }

    void dyndns_set_hostname(const char *hn)
    {
        _dyndns_set_hostname(hn);
    }

    void dyndns_set_auth(const char *auth)
    {
        _dyndns_set_auth(auth);
    }

    bool dyndns_update()
    {
        return _dyndns_update();
    }
}
