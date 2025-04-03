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

#define DO_PRODUCTION

#include "esp_log.h"
#include <sys/time.h>

#include "Acme.h"

static Acme *ac = 0;
static const char *tag = "acme c";
static httpd_handle_t wsrv = 0; // unsecure web server, for validating ACME queries

static void _acme_init()
{
    if (ac != 0)
        return;
    ac = new Acme();
}

static bool _acme_loop(time_t now)
{
    return ac->loop(now);
}

static void _acme_set_fs_prefix(const char *p)
{
    ac->setFsPrefix(p);
}

static void _acme_set_filename_prefix(const char *p)
{
    ac->setFilenamePrefix(p);
}

void _acme_set_url(const char *u)
{
    ac->setUrl(u);
}

void _acme_set_email(const char *e)
{
    ac->setEmail(e);
}

void _acme_set_account_key_filename(const char *fn)
{
    ac->setAccountKeyFilename(fn);
}

void _acme_set_account_filename(const char *fn)
{
    ac->setAccountFilename(fn);
}

void _acme_set_certkey_filename(const char *fn)
{
    ac->setCertKeyFilename(fn);
}

void _acme_set_order_filename(const char *fn)
{
    ac->setOrderFilename(fn);
}

void _acme_set_certificate_filename(const char *fn)
{
    ac->setCertificateFilename(fn);
}

void _acme_set_acme_server(const char *url)
{
    ac->setAcmeServer(url);
}

void _acme_create_new_account()
{
    ac->CreateNewAccount();
}

void _acme_create_new_order()
{
    ac->CreateNewOrder();
}

void _acme_generate_account_key()
{
    ac->GenerateAccountKey();
}

void _acme_generate_certificate_key()
{
    ac->GenerateCertificateKey();
}

bool _acme_have_valid_certificate()
{
    return ac->HaveValidCertificate();
}

void _acme_set_webserver(httpd_handle_t srv)
{
    if (ac)
        ac->setWebServer(srv);
    else
        ESP_LOGE(tag, "%s: not initialized", __FUNCTION__);
}

static const mbedtls_x509_crt *_acme_get_certificate()
{
    return ac->getCertificate();
}

static const mbedtls_pk_context *_acme_get_account_key()
{
    return ac->getAccountKey();
}

static const mbedtls_pk_context *_acme_get_certkey()
{
    return ac->getCertificateKey();
}

static const uint8_t *_acme_read_account_key()
{
    int len;
#ifdef CONFIG_DO_PRODUCTION
    const uint8_t *r = ac->ReadFile("/fs/acme/production/account.pem", &len);
#else
    const uint8_t *r = ac->ReadFile("/fs/acme/staging/account.pem", &len);
#endif
    return (const uint8_t *)r;
}

static const uint8_t *_acme_read_certificate()
{
    int len;
#ifdef CONFIG_DO_PRODUCTION
    const uint8_t *r = ac->ReadFile("/fs/acme/production/certificate.pem", &len);
#else
    const uint8_t *r = ac->ReadFile("/fs/acme/staging/certificate.pem", &len);
#endif
    return (const uint8_t *)r;
}

static const uint8_t *_acme_read_cert_key()
{
    int len;
#ifdef CONFIG_DO_PRODUCTION
    const uint8_t *r = ac->ReadFile("/fs/acme/production/certkey.pem", &len);
#else
    const uint8_t *r = ac->ReadFile("/fs/acme/staging/certkey.pem", &len);
#endif
    return (const uint8_t *)r;
}

extern "C"
{
    /*
     * Startup and such
     */
    void acme_init()
    {
        _acme_init();
    }

    bool acme_loop(time_t now)
    {
        return _acme_loop(now);
    }

    /*
     * Setters
     */
    void acme_set_url(const char *u)
    {
        _acme_set_url(u);
    }

    void acme_set_account_key_filename(const char *fn)
    {
        _acme_set_account_key_filename(fn);
    }

    void acme_set_account_filename(const char *fn)
    {
        _acme_set_account_filename(fn);
    }

    void acme_set_certkey_filename(const char *fn)
    {
        _acme_set_certkey_filename(fn);
    }

    void acme_set_order_filename(const char *fn)
    {
        _acme_set_order_filename(fn);
    }

    void acme_set_email(const char *e)
    {
        _acme_set_email(e);
    }

    void acme_set_fs_prefix(const char *p)
    {
        _acme_set_fs_prefix(p);
    }

    void acme_set_filename_prefix(const char *p)
    {
        _acme_set_filename_prefix(p);
    }

    void acme_set_acme_server(const char *url)
    {
        _acme_set_acme_server(url);
    }

    void acme_set_certificate_filename(const char *fn)
    {
        _acme_set_certificate_filename(fn);
    }

    /*
     * Getters
     */
    const mbedtls_x509_crt *acme_get_certificate()
    {
        return _acme_get_certificate();
    }

    const mbedtls_pk_context *acme_get_account_key()
    {
        return _acme_get_account_key();
    }

    const mbedtls_pk_context *acme_get_certkey()
    {
        return _acme_get_certkey();
    }

    /*
     * Cause action
     */
    void acme_create_new_account()
    {
        _acme_create_new_account();
    }

    void acme_create_new_order()
    {
        _acme_create_new_order();
    }

    void acme_generate_account_key()
    {
        _acme_generate_account_key();
    }

    void acme_generate_certificate_key()
    {
        _acme_generate_certificate_key();
    }

    bool acme_have_valid_certificate()
    {
        return _acme_have_valid_certificate();
    }

    void acme_set_webserver(httpd_handle_t srv)
    {
        _acme_set_webserver(srv);
    }

    // Cheap solution
    httpd_handle_t acme_start_webserver()
    {
        httpd_config_t wcfg = HTTPD_DEFAULT_CONFIG();

        if (httpd_start(&wsrv, &wcfg) != ESP_OK) {
            ESP_LOGE(tag, "%s: failed to start", __FUNCTION__);
            return 0;
        }
        // acme_set_webserver(wsrv);

        return wsrv;
    }

    void acme_stop_webserver()
    {
        if (wsrv)
            httpd_stop(wsrv);
        wsrv = 0;
    }

    /*
     * Read cert/key from fs
     */
    const uint8_t *acme_read_account_key()
    {
        return _acme_read_account_key();
    }

    const uint8_t *acme_read_certificate()
    {
        return _acme_read_certificate();
    }

    const uint8_t *acme_read_cert_key()
    {
        return _acme_read_cert_key();
    }
}
