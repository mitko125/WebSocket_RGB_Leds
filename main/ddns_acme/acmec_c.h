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

#ifdef __cplusplus
extern "C" {
#endif
  void acme_init();
  bool acme_loop(time_t);
  void acme_set_url(const char *u);
  void acme_set_account_key_filename(const char *fn);
  void acme_set_account_filename(const char *fn);
  void acme_set_certkey_filename(const char *fn);
  void acme_set_order_filename(const char *fn);
  void acme_set_email(const char *e);
  void acme_set_filename_prefix(const char *p);
  void acme_set_fs_prefix(const char *p);
  void acme_set_acme_server(const char *url);
  void acme_set_certificate_filename(const char *fn);

  const mbedtls_x509_crt *acme_get_certificate();
  const mbedtls_pk_context *acme_get_account_key();
  const mbedtls_pk_context *acme_get_certkey();

  const uint8_t *acme_read_account_key();
  const uint8_t *acme_read_certificate();
  const uint8_t *acme_read_cert_key();

  void acme_create_new_account();
  void acme_create_new_order();
  void acme_generate_account_key();
  void acme_generate_certificate_key();
  bool acme_have_valid_certificate();
  void acme_set_webserver(httpd_handle_t srv);
  httpd_handle_t acme_start_webserver();
  void acme_stop_webserver();

#ifdef __cplusplus
}
#endif
