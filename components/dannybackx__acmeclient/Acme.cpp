/*
 * This module implements the ACME (Automated Certicifate Management Environment) protocol.
 * A client for Let's Encrypt (https://letsencrypt.org).
 *
 * ACME relies on the presence of a web server for validation.
 * The IoT device can implement its own web server, we'll register for servicing just the
 * required file, only in the time that the ACME server needs it. (At the time of this writing
 * Letsencrypt.org's ACME service queries you four times from different addresses, very quickly.)
 *
 * You'll need to ensure that the IoT device is reachable for normal http, e.g. by redirecting
 * traffic for the right hostname to it from a Raspberry Pi based nginx.
 * Obviously for business traffic afterwards is may be necessary to redirect https as well.
 *
 * We're implementing ACME v2 (RFC 8555), which has status "proposed standard".
 * ACME v1 has risks and should be avoided.
 *
 * Copyright (c) 2019, 2020, 2021, 2022, 2023, 2024 Danny Backx
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

#include "esp_log.h"

#include "Acme.h"

#include <sys/socket.h>
#include <lwip/etharp.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/x509_csr.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>

#include <dirent.h>

/*
 * Global variable needs to be defined and initialized
 */
Acme	*_acme = 0;

/*
 * CTOR / DTOR
 */
Acme::Acme() {
  _acme = this;

  directory = 0;
  account = 0;
  order = 0;
  challenge = 0;
  account_location = 0;
  qt = query_unknown;
  retry_after = 0;
  nonce = 0;
  reply_buffer = 0;
  reply_buffer_len = 0;
  http01_ix = -1;
  last_run = 0;
  certificate = 0;

  acme_url = 0;
  alt_urls = 0;
  email_address = 0;
  acme_server_url = 0;
  account_fn = 0;
  account_key_fn = 0;
  order_fn = 0;
  cert_key_fn = 0;
  cert_fn = 0;

  ftp_server = 0;
  ftp_user = ftp_pass = 0;
  ftp_path = 0;

  webserver = 0;
  ws_registered = false;
  ovf = 0;

  accountkey = 0;
  certkey = 0;
  rsa = 0;
  root_certificate = 0;
  root_certificate_fn = 0;

  wait_for_timesync = time_synced = false;

  filename_prefix = "";
  fs_prefix = 0;

  connected = false;
  ignore_connected = true;

  ctr_drbg = (mbedtls_ctr_drbg_context *)calloc(1, sizeof(mbedtls_ctr_drbg_context));
  mbedtls_ctr_drbg_init(ctr_drbg);

  entropy = (mbedtls_entropy_context *)calloc(1, sizeof(mbedtls_entropy_context));
  mbedtls_entropy_init(entropy);

  int err;
  if ((err = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, NULL, 0))) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_ctr_drbg_seed failed %d %s", err, buf);
  }

#if 0
  ESP_LOGI(acme_tag, "ACME Configuration summary : %s", config->runAcme() ? "active" : "disabled");
  ESP_LOGI(acme_tag, "\tServer URL : %s", config->acmeServerUrl());
  ESP_LOGI(acme_tag, "\temail address : %s", config->acmeEmailAddress());
  ESP_LOGI(acme_tag, "\tMy URL : %s", config->acmeUrl());
  ESP_LOGI(acme_tag, "\tAccount private key : %s", config->getAccountKeyFileName());
  ESP_LOGI(acme_tag, "\tCertificate private key : %s", config->getAcmeCertificateKeyFileName());
  ESP_LOGI(acme_tag, "\tAccount info file : %s", config->getAcmeAccountFileName());
  ESP_LOGI(acme_tag, "\tOrder info file : %s", config->getAcmeOrderFileName());
#endif
}

Acme::~Acme() {
  ClearAccount();
  ClearOrder();
  ClearChallenge();
  ClearDirectory();
  if (nonce)
    free(nonce);
  if (reply_buffer)
    free(reply_buffer);
  reply_buffer_len = 0;
  if (account_location)
    free(account_location);
  if (retry_after)
    free(retry_after);

  free(rsa);
  rsa = 0;
  free(entropy);
  entropy = 0;
  free(ctr_drbg);
  ctr_drbg = 0;

  if (certificate) {
    mbedtls_x509_crt_free(certificate);
    free(certificate);
    certificate = 0;
  }
}

bool Acme::checkConfig() {
  if (acme_url == 0)
    return false;
  return true;
}

void Acme::GenerateAccountKey() {
  accountkey = GeneratePrivateKey();
  rsa = mbedtls_pk_rsa(*accountkey);
  if (account_key_fn)
    WritePrivateKey(accountkey, account_key_fn);
}

void Acme::GenerateCertificateKey() {
  certkey = GeneratePrivateKey();
  if (cert_key_fn)
    WritePrivateKey(certkey, cert_key_fn);
}

void Acme::ignoreConnected(bool ignore) {
}

/*
 * Private keys
 * Very simplistic setter/getters.
 * Assumption is to pass a pointer, the original objects are managed elsewhere if supplied.
 * There will be a leak if you allow the class to read from a file, as well as supplying a key.
 * Setters also write the key into a file.
 */
mbedtls_pk_context *Acme::getAccountKey() {
  if (accountkey == 0) {
    ReadAccountKey();
  }
  return accountkey;
}

mbedtls_pk_context *Acme::getCertificateKey() {
  if (certkey == 0) {
    ReadCertKey();
  }
  return certkey;
}

void Acme::setAccountKey(mbedtls_pk_context *ak) {
  accountkey = ak;
  if (accountkey) {
    rsa = mbedtls_pk_rsa(*accountkey);
    if (account_key_fn)
      WritePrivateKey(accountkey, account_key_fn);
  }
}

void Acme::setCertificateKey(mbedtls_pk_context *ck) {
  certkey = ck;
  if (certkey && cert_key_fn)
    WritePrivateKey(certkey, cert_key_fn);
}

/*
 * Network connect / disconnect handlers.
 * These use the esp-idf API for such functions.
 */
void Acme::NetworkConnected(void *ctx, wifi_event_sta_connected_t *event) {
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);

  connected = true;

  /*
   * Get startup info :
   * - the API calls for the ACME server
   * - an initial nonce
   * - our account and order status
   * See if we already have a local certificate
   *
   * FIX ME it may be a good idea to postpone the network calls.
   * Now we do them at each reboot...
   */
  if (time_synced || !wait_for_timesync) {
    QueryAcmeDirectory();
    RequestNewNonce();
    RequestNewAccount(email_address, true);	// This looks up the account, doesn't create one.

    ReadCertificate();
  }
}

void Acme::NetworkDisconnected(void *ctx, wifi_event_sta_disconnected_t *event) {
  connected = false;
  time_synced = false;
}

void Acme::WaitForTimesync(bool w) {
  wait_for_timesync = w;
}

void Acme::TimeSync(struct timeval *tp) {
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  time_synced = true;
}

/*
 * This is supposed to get called periodically to continue work.
 * The parameter should be the current timestamp.
 *
 * Two types of action occur :
 *  - trigger the ACME request engine (finite state machine) to advance order status
 *  - check if the current certificate should be renewed, and cause that (which stumbles into the above)
 *    The last_run member ensures we either do this at reboot, or only once per hour.
 *
 * Returns true if there was a change to the certificate.
 */
bool Acme::loop(time_t now) {
  if (wait_for_timesync && !time_synced)
    return false;

  // Avoid calling ACME server if we are way before renewal 
  if (certificate != 0) {
    time_t until = TimeMbedToTimestamp(certificate->valid_to);
    time_t month = 60 * 60 * 24 * 31;

    if (now < until - month) {
      ESP_LOGD(acme_tag, "Still before one month grace period");
      return false;
    }
  }

  // Closing in on renewal, let's continue
  if (directory == 0) {
    QueryAcmeDirectory();
    RequestNewNonce();
    RequestNewAccount(email_address, true);	// This looks up the account, doesn't create one.

    ReadCertificate();
  }

  if (order) {
    if (AcmeProcess(now))
      return true;
    return false;	// FIXME ? Only look into renewal if we're not processing here.
  }

  // Only do stuff on first call or wait an hour
  if ((last_run != 0) && (now - last_run < 3600))
      return false;
  last_run = now;

  // If we have a certificate, are we inside the renewal time range
  if (certificate == 0)
    return false;
  time_t until = TimeMbedToTimestamp(certificate->valid_to);
  time_t month = 60 * 60 * 24 * 31;

  // TODO
  if (until - month < now) {
    ESP_LOGD(acme_tag, "Renewing certificate from %s", __FUNCTION__);
    RenewCertificate();
  }
  return false;
}

/*
 * This runs the engine to reacquire a certificate.
 * RFC 8555 describes the states the server objects can be in; the client side must match that,
 * but also keep track of a couple of other state aspects :
 * - we may have "order = valid" but did we download the certificate yet ?
 * - ..
 *
 * This function does not start the order process, see RenewCertificate(), but advances it once it's started.
 * This function also doesn't create private keys, use the public API to do that or to supply them.
 *
 * Returns true if a (new) certificate was downloaded
 */
static int process_count = 5;

bool Acme::AcmeProcess(time_t now) {
  if (! checkConfig())
    return false;		// Silent

  /*
   * Note keep the two checks in this order.
   * If directory == 0 we only print limited number of error messages.
   */
  if (process_count-- < 0) {
    return false;
  }
  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s: no directory", __FUNCTION__);
    return false;
  }

  ESP_LOGD(acme_tag, "%s", __FUNCTION__);

  if (account == 0) {
    ESP_LOGE(acme_tag, "%s account 0", __FUNCTION__);
    if (! ReadAccountInfo()) {
      ESP_LOGI(acme_tag, "%s requesting new account", __FUNCTION__);
      RequestNewAccount(email_address, true);
      ESP_LOGI(acme_tag, "%s writing new account", __FUNCTION__);
      WriteAccountInfo();
    }
    if (account == 0) {
      ESP_LOGE(acme_tag, "%s: fail, no account", __FUNCTION__);
      return false;
    }
  }

  if (order == 0) {	// We haven't read storage yet, and we've not been kickstarted by the application.
    ESP_LOGD(acme_tag, "%s Read order info", __FUNCTION__);
    ReadOrderInfo();
  }
  if (order == 0)
    return false;		// Return silently

  if (order->status == 0) {
    ESP_LOGD(acme_tag, "%s order status 0", __FUNCTION__);
    ReadOrderInfo();
    if (order == 0 || order->status == 0) {
      ESP_LOGD(acme_tag, "%s request new order", __FUNCTION__);
      RequestNewOrder(acme_url);
      WriteOrderInfo();
      return false;
    }
  }
  if (order->status == 0) {
    ESP_LOGD(acme_tag, "%s order status 0", __FUNCTION__);
    return false;
  }

  // Check deeper
  bool invalid = false;
  if (challenge && strcmp(challenge->status, acme_status_invalid) == 0) {
    ESP_LOGI(acme_tag, "%s : %s challenge, starting a new order", __FUNCTION__, acme_status_invalid);
    invalid = true;
  } else if (challenge && challenge->challenges) {
    for (int i=0; challenge->challenges[i].status; i++)
      if (strcmp(challenge->challenges[i].status, acme_status_invalid) == 0) {
	ESP_LOGI(acme_tag, "%s : %s challenge[%d], starting a new order", __FUNCTION__, acme_status_invalid, i);
        invalid = true;
	break;
      }
  }
  if (invalid) {
    RequestNewOrder(acme_url);
    WriteOrderInfo();
    return false;
  }

  if (strcmp(order->status, acme_status_pending) == 0) {
    // Check if we have challenges ongoing
    bool ongoing = false;

    if (challenge && challenge->challenges) {
      for (int i=0; challenge->challenges[i].status; i++) {
        ESP_LOGD(acme_tag, "%s: challenge %d %s %s active %s",  __FUNCTION__, i,
	  challenge->challenges[i]._type,
	  challenge->challenges[i].status,
          challenge->challenges[i].active ? "true" : "false");
	if (challenge->challenges[i].active)
	  ongoing = true;
      }
    }
    if (ongoing) {
      GetOrderStatus();
      WriteOrderInfo();
    } else {
      return_status ok = ValidateOrder();
      ESP_LOGI(acme_tag, "%s: ValidateOrder -> %s", __FUNCTION__, returnstatus2string(ok));
      if (ok != status_fail) {
	WriteOrderInfo();
      } else {
	OrderRemove();
	return false;
      }
    }
  }

  // Crash prevention
  if (order == 0 || order->status == 0)
    return false;

  if (strcmp(order->status, acme_status_ready) == 0) {
    FinalizeOrder();
    WriteOrderInfo();
  }

  /*
   * Assuming we're running a separate task from the main application,
   * if we get a "processing" state here then we'll just wait.
   */
  if (strcmp(order->status, acme_status_processing) == 0) {
    if (order->retry_after) {
      int delay_seconds = atoi(order->retry_after);
      vTaskDelay(delay_seconds * 1000 / portTICK_PERIOD_MS);

      ESP_LOGD(acme_tag, "%s: status %s, waited %d", __FUNCTION__, order->status, delay_seconds);
    } else if (retry_after) {
      int delay_seconds = atoi(retry_after);
      vTaskDelay(delay_seconds * 1000 / portTICK_PERIOD_MS);

      ESP_LOGD(acme_tag, "%s: status %s, waited %d", __FUNCTION__, order->status, delay_seconds);
    } else {
      ESP_LOGE(acme_tag, "%s: status %s, ???", __FUNCTION__, order->status);
    }

    // After the wait, check order status on the server
    GetOrderStatus();
    WriteOrderInfo();
  }

  if (strcmp(order->status, acme_status_downloaded) == 0) {
    // There shouldn't be anything here, but if the downloaded file goes bust, download it again.
    if (certificate == 0) {
      free(order->status);
      order->status = strdup(acme_status_valid);
      WriteOrderInfo();
    }
  }
  if (strcmp(order->status, acme_status_valid) == 0) {
    bool ok = false;
    if (order->certificate) {
      ok = DownloadCertificate();
      WriteOrderInfo();
    }

    if (ws_registered)
      DisableLocalWebServer();

    if (ok) {
      free(order->status);
      order->status = strdup(acme_status_downloaded);		// an additional status
    }
    WriteOrderInfo();

    if (ok)
      return true;
  }

  if (strcmp(order->status, acme_status_invalid) == 0) {
    // Something went wrong with this order, need to restart a new order
    RequestNewOrder(acme_url);
    WriteOrderInfo();

    if (ws_registered)
      DisableLocalWebServer();

    return false;
  }
  
  return false;
}

bool Acme::CreateNewAccount() {
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  if (!ignore_connected && !connected) {
    ESP_LOGE(acme_tag, "%s: not connected", __FUNCTION__);
    return false;
  }
  if (wait_for_timesync && !time_synced) {
    ESP_LOGE(acme_tag, "%s: timesync NOK, %s %s", __FUNCTION__,
      wait_for_timesync ? "yes" : "no",
      time_synced ? "yes" : "no");
    return false;
  }
  if (directory == 0) {
    ESP_LOGD(acme_tag, "%s: directory NULL", __FUNCTION__);
    QueryAcmeDirectory();
    RequestNewNonce();
  }
  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s: directory NULL", __FUNCTION__);
    return false;
  }

  ESP_LOGI(acme_tag, "%s: start", __FUNCTION__);
  if (email_address == 0) {
    ESP_LOGE(acme_tag, "%s failed : no email address", __FUNCTION__);
    return false;
  }

  ESP_LOGI(acme_tag, "%s: check whether account already exists", __FUNCTION__);
  // Check if it exists already
  if (RequestNewAccount(email_address, true)) {
    ESP_LOGI(acme_tag, "%s: account exists", __FUNCTION__);
    WriteAccountInfo();
    return true;	// Return successfully then
  }

  ESP_LOGI(acme_tag, "%s: creating account %s ...", __FUNCTION__, email_address);
  // Otherwise, try to create one
  bool ok = RequestNewAccount(email_address, false);
  if (ok) {
    ESP_LOGI(acme_tag, "%s: success : account %s created", __FUNCTION__, email_address);
    WriteAccountInfo();
  } else {
    ESP_LOGE(acme_tag, "%s: failed", __FUNCTION__);
  }

  return ok;
}

/*
 * This creates a structure so the process gets triggered
 */
void Acme::CreateNewOrder() {
  ESP_LOGI(acme_tag, "%s()", __FUNCTION__);
  ClearOrder();
  order = (Order *)malloc(sizeof(Order));
  memset((void *)order, 0, sizeof(Order));
}

/*
 * Strings need to be translated into proper format, see the JWS RFC : https://tools.ietf.org/html/rfc7515 .
 * Caller needs to free the result.
 */
char *Acme::Base64(const char *s) {
  size_t olen;

  if (s == 0) {
    ESP_LOGD(acme_tag, "%s : null", __FUNCTION__);
    return 0;
  }

  int sl = strlen(s);
  if (sl == 0) {
    ESP_LOGD(acme_tag, "%s : empty string", __FUNCTION__);
    char *r = (char *)malloc(1);
    *r = 0;
    return r;
  }

  (void) mbedtls_base64_encode(0, 0, &olen, (const unsigned char *)s, sl);
  char *r = (char *)malloc(olen + 1);
  (void) mbedtls_base64_encode((unsigned char *)r, olen+1, &olen, (const unsigned char *)s, sl);

  // Replace some characters by acceptable ones, without making the string longer. Also in the RFCs.
  for (int i=0; i<=olen; i++)
    if (r[i] == '+')
      r[i] = '-';
    else if (r[i] == '/')
      r[i] = '_';
#if 1
    // Danny suspicious 27/07/2023
    else if (r[i] == '=')
      r[i] = 0;	
#endif
  return r;
}

// And the opposite
char *Acme::Unbase64(const char *s) {
  int len = strlen(s);
  char *r = (char *)malloc(len+4);	// For a trailing 0 and up to 2 trailing '='
  for (int i=0; i<=len; i++)
    if (s[i] == '-')
      r[i] = '+';
    else if (s[i] == '_')
      r[i] = '/';
    else if (s[i] == 0) {
      r[i]   = '=';
      r[i+1] = '=';
      r[i+2] = 0;
    } else
      r[i] = s[i];

  size_t olen = 0;
  (void) mbedtls_base64_decode(0, 0, &olen, (const unsigned char *)r, len);

  ESP_LOGD(acme_tag, "%s: strlen -> %d, olen %d", __FUNCTION__, len, olen);
  char *obuf = (char *)malloc(olen+1);
  if (obuf == 0) {
    ESP_LOGE(acme_tag, "%s: malloc -> 0, errno %d", __FUNCTION__, errno);
    free(r);
    return 0;
  }
  int err = mbedtls_base64_decode((unsigned char *)obuf, olen+1, &olen, (const unsigned char *)r, len);
  if (err != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_base64_decode error %d %s", __FUNCTION__, err, buf);
    free(r);
    free(obuf);
    return 0;
  }
  free(r);
  return obuf;
}

/*
 * Strings need to be translated into proper format, see the JWS RFC : https://tools.ietf.org/html/rfc7515 .
 * Caller needs to free the result.
 *
 * This version includes a length parameter.
 */
char *Acme::Base64(const char *s, int len) {
  if (s == 0)
    return 0;

  size_t olen;
  (void) mbedtls_base64_encode(0, 0, &olen, (const unsigned char *)s, len);
  ESP_LOGD(acme_tag, "%s(_,%d) olen %d", __FUNCTION__, len, olen);

  char *r = (char *)malloc(olen + 1);
  (void) mbedtls_base64_encode((unsigned char *)r, olen+1, &olen, (const unsigned char *)s, len);

  // Replace some characters by acceptable ones, without making the string longer. Also in the RFCs.
  for (int i=0; i<=olen; i++)
    if (r[i] == '+')
      r[i] = '-';
    else if (r[i] == '/')
      r[i] = '_';
    else if (r[i] == '=')
      r[i] = 0;	

  return r;
}

/*
 * Make an ACME message, this version makes the ones that include a "jwk" field.
 *
 * Some of the relevant parts of RFC 8555 (§6.2) :
 *   It must have the fields "alg", "nonce", "url", and either "jwk" or "kid".
 *   newAccount and revokeCert messages must use jwk, this field must contain the public key
 *   corresponding to the private key used to sign the JWS.
 *   All other requests are signed using an existing account, and there must be a kid field
 *   which contains the account URL received by POSTing to newAcount.
 *
 * So this must only be used in newAccount or revokeCert.
 *
 * {"url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct", "jwk": {"kty": "RSA",
 *  "n": "...", "e": "AQAB"}, "alg": "ES256", "nonce": "U8b_2ZGRATuySa9yPOF3JDN4JXTyEdAfrL--WTzqYKQ"}
 */
char *Acme::MakeMessageJWK(char *url, char *payload, char *jwk) {
  ESP_LOGD(acme_tag, "%s(%s,%s,%s)", __FUNCTION__, url, payload, jwk);

  int sz = 0;
  char *p_rotected = 0;

  char *my_nonce = GetNonce();
  ESP_LOGD(acme_tag, "%s use nonce %s", __FUNCTION__, my_nonce);
  if (my_nonce == 0)
    return 0;

  // First use snprintf to calculate size, then allocate, then actually make the message
  // "{\"url\": \"%s\", \"jwk\": %s, \"alg\": \"RS256\", \"nonce\": \"%s\"}",
  sz = snprintf(p_rotected, sz, acme_message_jwk_template1, url, jwk, my_nonce);
  if (sz < 0)
    return 0;
  sz++;
  p_rotected = (char *)malloc(sz);
  // "{\"url\": \"%s\", \"jwk\": %s, \"alg\": \"RS256\", \"nonce\": \"%s\"}",
  snprintf(p_rotected, sz, acme_message_jwk_template1, url, jwk, my_nonce);
  ESP_LOGD(acme_tag, "p_rotected 2 (sz %d, len %d) %s", sz, strlen(p_rotected), p_rotected);

  char *p_rotected64 = Base64(p_rotected);
  free(p_rotected);
  char *p_ayload = Base64(payload);
  ESP_LOGD(acme_tag, "%s call Signature", __FUNCTION__);
  char *s_ignature = Signature(p_rotected64, p_ayload);

  sz = 0;
  char *js = 0;
  // First use snprintf to calculate size, then allocate, then actually make the message
  // "{\n  \"protected\": \"%s\",\n  \"payload\": \"%s\",\n  \"signature\": \"%s\"\n}",
  sz = snprintf(js, sz, acme_message_jwk_template2, p_rotected64, p_ayload, s_ignature);
  if (sz < 0) {
    free(p_ayload);
    free(s_ignature);
    return 0;
  }
  sz++;
  js = (char *)malloc(sz);
  // "{\n  \"protected\": \"%s\",\n  \"payload\": \"%s\",\n  \"signature\": \"%s\"\n}",
  snprintf(js, sz, acme_message_jwk_template2, p_rotected64, p_ayload, s_ignature);
  free(p_ayload);
  free(s_ignature);
  ESP_LOGD(acme_tag, "js 2 (sz %d len %d) %s", sz, strlen(js), js);

  return js;
}

/*
 * Caller must free
 *
 * This basically prints out the N (public key modulus) field from the key in the RSA context pointer.
 * We're extracting the N and E mpi's. Note that their type is char * but they're not strings.
 * Can start with 0 if not allocated properly, and not null-terminated. Hence the two-parameter call to Base64().
 */
char *Acme::MakeJWK() {
  int err;

  int ne = 4;						// E will be at the rear end of this array
  unsigned char	E[4];
  int nl = mbedtls_rsa_get_len(rsa);
  unsigned char *N = (unsigned char *)malloc(nl);	// Allocate exactly long enough, don't add one more for trailing 0.

  if ((err = mbedtls_rsa_export_raw(rsa, N, nl, /* P */ 0, 0, /* Q */ 0, 0, /* D */ 0, 0, E, ne)) != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: failed rsa_export_raw %d %s", __FUNCTION__, err, buf);
    return 0;
  }

  // E is at the rear end of this array, point q to it
  char *q = (char *)E;
  for (; *q == 0; q++,ne--);			// Skip initial zeroes

  ESP_LOGD(acme_tag, "%s: call Base64(_,%d)", __FUNCTION__, nl);
  char *bN = Base64((char *)N, nl);		// Note RFC remark not to apply padding, N has been allocated exactly the right size
  ESP_LOGD(acme_tag, "%s: call Base64(_,%d)", __FUNCTION__, ne);
  char *bE = Base64(q, ne);			// This returns "AQAB" under normal circumstances

  ESP_LOGD(acme_tag, "%s: N %s, E %s", __FUNCTION__, bN, bE);

  free(N);

  int len = strlen(acme_jwk_template) + strlen((char *)bN) + strlen((char *)bE) + 4;
  char *r = (char *)malloc(len);
  sprintf(r, acme_jwk_template, bN, bE);
  free(bN);
  free(bE);

  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, r);

  return r;
}

/*
 * RFC 8555 (ACME v2) says (§6.2) : encapsulate payload in a JWS (RFC7515) object,
 * using Flattened JSON Serialization.
 *
 * RFC 7518 (JWS) §3.3 : A key of size 2048 bits or larger MUST be used with these algorithms.
 *
 * Signature as specified by JWS (https://tools.ietf.org/html/rfc7515).
 * This must be JSON Web Signature (see RFC 8555, §6.1).
 *
 * Parameters are already base64-url formatted
 *
 * Caller should free the result
 */
char *Acme::Signature(const char *pr, const char *pl) {
  int ret;
  char buf[80];

  ESP_LOGD(acme_tag, "%s pr len %d pl len %d (%s,%s)", __FUNCTION__, strlen(pr), strlen(pl), pr, pl);

  int len = strlen(pr) + strlen(pl) + 4;
  char *bb = (char *)malloc(len);
  sprintf(bb, "%s.%s", pr, pl);
  ESP_LOGD(acme_tag, "signing input (length %d) {%s}", strlen((char *)bb), bb);

  size_t signature_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
  unsigned char *signature = (unsigned char *)malloc(signature_size+1);
  if (! signature) {
    ESP_LOGE(acme_tag, "calloc failed, mbedtls_pk_get_len %d", mbedtls_pk_get_len(accountkey));
    free(bb);
    return 0;
  }
  ESP_LOGD(acme_tag, "%s: signature_size %d", __FUNCTION__, signature_size);

  int hash_size = 32;
  unsigned char *hash = (unsigned char *)calloc(1, hash_size);
  if (hash == 0) {
    ESP_LOGE(acme_tag, "%s: calloc(%d) failed", __FUNCTION__, hash_size);
    free(signature);
    free(bb);
    return 0;
  }

  const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mdi) {
    ESP_LOGE(acme_tag, "mbedtls_md_info_from_type: md_info not found");
    free(signature);
    free(hash);
    return 0;
  }
  ret = mbedtls_md(mdi, (const unsigned char *)bb, strlen(bb), (unsigned char *)hash);
  free(bb); bb = 0;
  if (ret != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_md failed %s (0x%04x)", buf, -ret);
    free(signature);
    free(hash);
    return 0;
  }

  size_t siglen = 0;
  ret = mbedtls_pk_sign(accountkey, MBEDTLS_MD_SHA256, hash, hash_size, signature, signature_size, &siglen, mbedtls_ctr_drbg_random, ctr_drbg);
  ESP_LOGD(acme_tag, "%s: siglen %d", __FUNCTION__, siglen);
  if (ret != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_pk_sign failed %s (0x%04x)", buf, -ret);
    free(signature);
    free(hash);
    return 0;
  }

  ESP_LOGD(acme_tag, "%s: signature size %d, siglen %d", __FUNCTION__, signature_size, siglen);

  /* Base64-encode and return.. it's important to use signature_size from mbedtls_pk_sign,
   * the signature can contain 0 bytes. */
  char *s = Base64((char *)signature, siglen);
  free(signature);

  return s;
}

/***************************************************
 * And now for real ACME ...
 *
 ***************************************************/
/*
 * Fetch the "directory" of the ACME server.
 * This gives us a set of URLs for our queries. Put this in a structure for later use.
 */
void Acme::QueryAcmeDirectory() {
  if (!ignore_connected && !connected) return;
  if (wait_for_timesync && !time_synced)
    return;
  if (acme_server_url == 0) {
    ESP_LOGE(acme_tag, "%s: no ACME server configured", __FUNCTION__);
    return;
  }

#if ! defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
  if (root_certificate_fn != 0 && root_certificate == 0)
    ReadRootCertificate();
  if (root_certificate == 0) {
    ESP_LOGE(acme_tag, "%s: failed, no root certificate", __FUNCTION__);
    return;
  }
#endif

  ESP_LOGI(acme_tag, "Querying directory at %s", acme_server_url);
  ClearDirectory();

  char *reply = PerformWebQuery(acme_server_url, 0, 0, 0);

  if (reply == 0) {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> 0, returning", __FUNCTION__);
    return;
  }

  ESP_LOGD(acme_tag, "%s: parsing JSON %s", __FUNCTION__, reply);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je)
  {
    ESP_LOGE(acme_tag, "Could not parse JSON");
    free(reply);
    return;
  }
  directory = (Directory *)malloc(sizeof(Directory));
  memset(directory, 0, sizeof(Directory));

#define SD(x,sx) 						\
	{							\
	  const char *s;					\
	  s = root[sx];						\
	  if (s) {						\
	    x = strdup(s);					\
	    ESP_LOGD(acme_tag, "New %s URL : %s", sx, x);	\
	  } else						\
	    x = 0;						\
	}

  SD(directory->newAccount, "newAccount");
  SD(directory->newNonce, "newNonce");
  SD(directory->newOrder, "newOrder");

  free(reply);

  if (directory->newAccount == 0 || directory->newNonce == 0 || directory->newOrder == 0)
    ESP_LOGE(acme_tag, "%s: incomplete results : newAccount %p newNonce %p newOrder %p", __FUNCTION__,
      directory->newAccount, directory->newNonce, directory->newOrder);
  else
    ESP_LOGD(acme_tag, "%s: ok", __FUNCTION__);
}

/*
 * Deallocate the structure with the server URLs, and its content.
 */
void Acme::ClearDirectory() {
  if (directory) {
    if (directory->newAccount) free(directory->newAccount);
    if (directory->newNonce) free(directory->newNonce);
    if (directory->newOrder) free(directory->newOrder);
    free(directory);
    directory = 0;
  }
}

/*
 * Nonce : this is an ACME v1 vs v2 difference : make sure the server only gets queries in a sequence.
 * Each ACME query will include the "nonce" that its predecessor received from the server.
 *
 * We send a HEAD query to the URL in the directory, and fetch the header "Replay-Nonce" in the reply.
 * This requires a 3 function implementation because the esp_http_client API doesn't expose reply headers except in an event handler.
 * The reply data is available though, go figure :-(
 */
bool Acme::RequestNewNonce() {
  esp_err_t			err;
  esp_http_client_config_t	httpc;
  esp_http_client_handle_t	client;

  ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s: no ACME directory", __FUNCTION__);
    return false;
  }

  if (nonce) {
    ESP_LOGE(acme_tag, "%s but nonce present (%s)", __FUNCTION__, nonce);

    free(nonce);
    nonce = 0;
  } else {
    ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  }

  if (directory->newNonce == 0) {
    ESP_LOGE(acme_tag, "%s: we have no newNonce URL", __FUNCTION__);
    return false;
  }

  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, directory->newNonce);

  memset(&httpc, 0, sizeof(httpc));
  httpc.url = directory->newNonce;
  httpc.event_handler = NonceHttpEvent;
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
  httpc.crt_bundle_attach = esp_crt_bundle_attach;
#else
  if (root_certificate)
    httpc.cert_pem = root_certificate;	// Required in esp-idf 4.3 for https
#endif

  client = esp_http_client_init(&httpc);

  SetAcmeUserAgentHeader(client);

  if ((err = esp_http_client_set_method(client, HTTP_METHOD_HEAD)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_method error %d %s", __FUNCTION__, err, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }
  ESP_LOGD(acme_tag, "%s set_method(HEAD) ok", __FUNCTION__);

  if ((err = esp_http_client_perform(client)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_perform error %d %s", __FUNCTION__, err, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }
  ESP_LOGD(acme_tag, "%s client_perform ok", __FUNCTION__);

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  nonce_use = 0;

  // It should already be there, so report back
  return (nonce != 0);
}

char *Acme::GetNonce() {
  nonce_use++;
  if (nonce_use == 1)
    return nonce;
  ESP_LOGD(acme_tag, "%s: nonce_use %d", __FUNCTION__, nonce_use);
  return NULL;
}

esp_err_t Acme::NonceHttpEvent(esp_http_client_event_t *event) {
  if (event->event_id == HTTP_EVENT_ON_HEADER) {
    ESP_LOGD("Acme", "%s: header %s value %s", __FUNCTION__, event->header_key, event->header_value);
    if (strcmp(event->header_key, acme_nonce_header) == 0)
      _acme->setNonce(event->header_value);
  }
  return ESP_OK;
}

/*
 * These are handlers called by HttpEvent() so we can pick up stuff from HTTP headers in replies from the ACME server.
 */
void Acme::setNonce(char *s) {
  if (nonce)
    free(nonce);
  nonce = strdup(s);
  nonce_use = 0;

  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, nonce);
}

void Acme::clearQueryHeaders(void) {
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  if (account_location)
    free(account_location);
  account_location = 0;
  if (retry_after)
    free(retry_after);
  retry_after = 0;
}

/*
 * This is needed because the location field is passed back in an HTTP header
 * Note the Location field is overloaded, so we're using flags to determine where to
 * put the info. That's the whole point of the QueryType stuff.
 */
void Acme::setLocation(const char *s) {
  switch (qt) {
  case query_order:
  case query_finalize:
    ESP_LOGD(acme_tag, "%s(%s) - %s (order %p)", __FUNCTION__, s, QueryTypeToString(qt), order);
    if (order) {
      if (order->location) free(order->location);
      order->location = strdup(s);
      WriteOrderInfo();
    } else {
      ESP_LOGE(acme_tag, "%s: no order", __FUNCTION__);
    }
    break;
  case query_account:
    ESP_LOGD(acme_tag, "%s(%s) - %s (account %p)", __FUNCTION__, s, QueryTypeToString(qt), account);
    if (account_location)
      free(account_location);
    account_location = strdup(s);
    if (account) {
      if (account->location)
        free((void *)account->location);
      account->location = strdup(s);
    }
    break;
  case query_unknown:
    break;
  }
}

const char *Acme::QueryTypeToString(query_type q) {
  switch (q) {
  case query_unknown:	return "unknown";
  case query_account:	return "account";
  case query_order:	return "order";
  case query_finalize:	return "finalize";
  default:		return "?";
  }
}

void Acme::setQueryType(query_type q) {
  qt = q;
}

void Acme::resetQueryType() {
  qt = query_unknown;
}

// This is needed because the retry-after field is passed back in an HTTP header
void Acme::setRetryAfter(const char *s) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, s);
  if (retry_after)
    free(retry_after);
  retry_after = strdup(s);
}

/*
 * Manage private key
 */
mbedtls_pk_context *Acme::GeneratePrivateKey() {
  mbedtls_pk_context	*key;
  int			ret;
  char			buf[80];

  ESP_LOGI(acme_tag, "Generating private key ...");

  key = (mbedtls_pk_context *)calloc(1, sizeof(mbedtls_pk_context));
  mbedtls_pk_init(key);
  mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

  if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, ctr_drbg, /* key size */ 2048, /* exponent */ 0x10001)) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_rsa_gen_key failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    free((void *)key);
    return 0;
  }
  return key;
}

/*
 * Read a private key from a file, caller can specify file name.
 * Prepends our path prefix prior to use.
 */
mbedtls_pk_context *Acme::ReadPrivateKey(const char *ifn) {
  mbedtls_pk_context *pk;

  int fnlen = strlen(filename_prefix) + strlen(ifn) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, ifn);

  int ret;
  char buf[80];

  pk = (mbedtls_pk_context *)calloc(1, sizeof(mbedtls_pk_context));
  mbedtls_pk_init(pk);
  if ((ret = mbedtls_pk_parse_keyfile(pk, fn, 0, mbedtls_ctr_drbg_random, ctr_drbg)) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_pk_parse_keyfile(%s) failed %s (0x%04x)", __FUNCTION__, fn, buf, -ret);
    free(fn);
    free((void *)pk);
    return 0;
  }

  ESP_LOGD(acme_tag, "%s: read key file (%s) ok", __FUNCTION__, fn);
  free(fn);
  return pk;
}

/*
 * Check (and create) directories in the path
 * This becomes sensible on a real filesystem like LittleFS (not on SPIFFS).
 */
void Acme::CreateDirectories(const char *path) {
  char *dir = strdup(path);

  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, dir);

  // Walk from the beginning to the end of the path

  int len = strlen(dir);
  for (int i=1; i<len; i++)
    if (dir[i] == '/') {
      // Temporarily terminate path here
      dir[i] = 0;

      ESP_LOGD(acme_tag, "%s(%s,%s)", __FUNCTION__, dir, filename_prefix);

      // If this is the prefix, skip
      if (fs_prefix && strcasecmp(dir, fs_prefix) != 0) {
	// If this directory doesn't exist, create it
	DIR *dp = opendir(dir);
	if (dp == 0) {
	  int err = mkdir(dir, 0777);
	  if (err == ESP_OK) {
	    ESP_LOGD(acme_tag, "%s: created directory %s", __FUNCTION__, dir);
	  } else {
	    ESP_LOGE(acme_tag, "%s: failed to create directory %s, %d %s", __FUNCTION__, dir,
	      err, esp_err_to_name(err));
	    return;
	  }
	} else {
	  ESP_LOGD(acme_tag, "%s : %s exists", __FUNCTION__, dir);
	  closedir(dp);
	}
      }

      // Restore path
      dir[i] = '/';
    }
  free(dir);
}

/*
 * Write a private key to a file, caller can specify file name.
 * Prepends our path prefix prior to use.
 */
void Acme::WritePrivateKey(mbedtls_pk_context *pk, const char *ifn) {
  int fnlen = strlen(filename_prefix) + strlen(ifn) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, ifn);
  ESP_LOGD(acme_tag, "WritePrivateKey(%s)", fn);

  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == 0) {
    ESP_LOGE(acme_tag, "%s: could not write private key to file %s", __FUNCTION__, fn);
    free(fn);
    return;
  }

  int ret, len;
  char buf[80];
  unsigned char keystring[2048];

  // PEM or DER ? Use file name suffix, default to PEM
  bool write_pem = true;

  if (write_pem) {
    if ((ret = mbedtls_pk_write_key_pem(pk, keystring, sizeof(keystring))) != 0) {
      mbedtls_strerror(ret, buf, sizeof(buf));
      ESP_LOGE(acme_tag, "%s: write_key_pem failed %s (0x%04x)", __FUNCTION__, buf, -ret);
      free(fn);
      return;
    }
  } else {
    if ((ret = mbedtls_pk_write_key_der(pk, keystring, sizeof(keystring))) != 0) {
      mbedtls_strerror(ret, buf, sizeof(buf));
      ESP_LOGE(acme_tag, "%s: write_key_der failed %s (0x%04x)", __FUNCTION__, buf, -ret);
      free(fn);
      return;
    }
  }

  len = strlen((char *)keystring);
  ESP_LOGD(acme_tag, "%s: private key len %d", __FUNCTION__, len);
  ESP_LOGD(acme_tag, "Key : %s", keystring);

  if (fwrite(keystring, 1, len, f) != len) {
    ESP_LOGE(acme_tag, "%s: write private key to %s failed, %d %s", __FUNCTION__, fn, errno, strerror(errno));
    fclose(f);
    free(fn);
    return;
  }
  if (fclose(f) != 0) {
    ESP_LOGE(acme_tag, "%s: write private key to %s failed, %d %s", __FUNCTION__, fn, errno, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGI(acme_tag, "%s: wrote private key to %s", __FUNCTION__, fn);
  free(fn);
}

/*
 * Write a private key to the file name from Config.
 */
void Acme::WritePrivateKey() {
  int ret, len;
  char buf[80];
  unsigned char keystring[2048];

  if ((ret = mbedtls_pk_write_key_pem(accountkey, keystring, sizeof(keystring))) != 0) {
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_pk_write_key_pem failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    return;
  }

  len = strlen((char *)keystring);
  ESP_LOGD(acme_tag, "%s: private key len %d", __FUNCTION__, len);
  ESP_LOGD(acme_tag, "Key : %s", keystring);

  int fnlen = strlen(account_key_fn) + strlen(filename_prefix) + 3;
  char *fn = (char *)malloc(fnlen);
  sprintf(fn, "%s/%s", filename_prefix, account_key_fn);

  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f) {
    fwrite(keystring, 1, len, f);
    fclose(f);
  } else {
    ESP_LOGE(acme_tag, "%s: could not write private key to file %s", __FUNCTION__, fn);
  }
  free(fn);
}

/*
 * Account handling
 * The "onlyExisting" parameter is used to check whether an account pre-exists. Don't use error logging then.
 */
bool Acme::RequestNewAccount(const char *contact, bool onlyExisting) {
  ESP_LOGD(acme_tag, "%s(%s,%s)", __FUNCTION__, contact,
    onlyExisting ? "onlyExisting" : "alwaysCreate");

  char *msg, *jwk, *payload;

  if (directory == 0) {
    ESP_LOGE(acme_tag, "%s fail, no directory", __FUNCTION__);
    return false;
  }

  if (rsa == 0) {
    ReadAccountKey();
    if (rsa == 0) {
      ESP_LOGE(acme_tag, "%s(%s) fail, rsa null", __FUNCTION__, contact);
      return false;
    }
  }

  if (contact) {	// email address is included
    // Check whether it starts with "mailto:"
    bool add_mailto = (strncasecmp(contact, acme_mailto, strlen(acme_mailto)) != 0);

    // Allocate just enough. The 10 is for small stuff + the onlyExisting bool.
    int len = strlen(new_account_template) + strlen(contact) + 10;
    if (add_mailto)
      len += strlen(acme_mailto);
    payload = (char *)malloc(len);

    // Create message
    sprintf(payload, new_account_template,
      add_mailto ? acme_mailto : "", contact,
      onlyExisting ? "true" : "false");
    ESP_LOGD(acme_tag, "%s(%s) msg %s", __FUNCTION__, contact, payload);
  } else {
    payload = strdup(new_account_template_no_email);
    ESP_LOGD(acme_tag, "%s(NULL) msg %s", __FUNCTION__, payload);
  }

  jwk = MakeJWK();
  if (jwk) {
    ESP_LOGD(acme_tag, "%s : jwk %s", __FUNCTION__, jwk);
    msg = MakeMessageJWK(directory->newAccount, payload, jwk);
    free(jwk);
  } else
    msg = MakeMessageJWK(directory->newAccount, payload, (char *)"");

  if (! msg) {
    ESP_LOGE(acme_tag, "%s: null message", __FUNCTION__);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : msg %s", __FUNCTION__, msg);

  // Ensure we already have an account, so we can store the location info when it arrives
  account = (Account *)malloc(sizeof(Account));
  memset((void *)account, 0, sizeof(Account));

  setQueryType(query_account);
  char *reply = PerformWebQuery(directory->newAccount, msg, acme_jose_json, 0);
  free(msg);
  resetQueryType();
  if (reply == 0) {
    ESP_LOGE(acme_tag, "%s PerformWebQuery -> null", __FUNCTION__);
    return false;
  }

  // Decode JSON reply
  ESP_LOGD(acme_tag, "%s: parsing JSON %s", __FUNCTION__, reply);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je)
  {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  /*
   * Depending on the kind of reply, reply_status can be a HTTP error code as a number (no quotes),
   * or an ACME status code like "valid".
   * ArduinoJson 6.x appears to have trouble with that unless you give it some love.
   *   And even then : the .as<const char *>() doesn't appear to help.
   * Fortunately we can just bail on this and have the caller request a new account.
   */
  const char *reply_status = root[acme_json_status].as<const char *>();
  const char *reply_detail = root[acme_json_detail].as<const char *>();
  const char *reply_type = root[acme_json_type].as<const char *>();

  ESP_LOGD(acme_tag, "JSON status \"%s\" -> %s", acme_json_status, reply_status ? reply_status : "null");
  if (reply_status == 0) {
    int reply_status_int = root[acme_json_status] | -1;
    ESP_LOGE(acme_tag, "JSON status \"%s\" -> %d, detail %s, type %s",
      acme_json_status, reply_status_int, reply_detail, reply_type);
  }

  if (reply_status && strcmp(reply_status, acme_status_valid) != 0) {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    if (!onlyExisting)
      ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return false;
  } else if (reply_status == 0) {
    /*
     * See above, this could be caused by e.g.
     *		{
     *		  "type": "urn:ietf:params:acme:error:accountDoesNotExist",
     *		  "detail": "No account exists with the provided key",
     *		  "status": 400
     *		}
     * but we can bail on this.
     */
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
    free(reply);
    return false;
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status '%s'", __FUNCTION__, reply_status);
  }

  ReadAccount(root);

  free(reply);
  return true;
}

// FIXME protect against missing fields, will now call strdup(0)
#if ARDUINOJSON_VERSION_MAJOR < 7
void Acme::ReadAccount(DynamicJsonDocument &json)
#else
void Acme::ReadAccount(JsonDocument &json)
#endif
{
  // account = (Account *)malloc(sizeof(Account));
  // memset((void *)account, 0, sizeof(Account));

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      account->x = strdup(x);							\
    } else {									\
      account->x = 0;								\
    }										\
  }

#define	BZZ2(x,y)								\
  {										\
    const char *x = json["key"][#y];						\
    if (x)									\
      account->x = strdup(x);							\
    else									\
      account->x = 0;								\
  }

  BZZ2(key_type, kty);
  BZZ2(key_id, n);
  BZZ2(key_e, e);

  BZZ(initialIp);
  BZZ(createdAt);
  BZZ(status);

  JsonObject jca = json["contact"];
  ESP_LOGD(acme_tag, "%s : %d contacts", __FUNCTION__, jca.size());
  account->contact = (char **)calloc(jca.size()+1, sizeof(char *));
  account->contact[jca.size()] = 0;
  for (int i=0; i<jca.size(); i++) {
    char ix[12];
    sprintf(ix, "%d", i);
    const char *cc = jca[ix];
    account->contact[i] = strdup(cc);
  }

  // Exception for the location field : when reading a ACME reply, this is in an HTTP header.
  // When reading from our saved file, this is in the JSON.
  // So only update the field if we read the JSON parameter, otherwise don't do a thing.
  const char *l = json["location"];

  if (account->location)
    free(account->location);
  if (account_location) {
    account->location = account_location;
    account_location = 0;
  } else if (l)
    account->location = strdup(l);

#undef BZZ
#undef BZZ2
}

void Acme::ClearAccount() {
  ESP_LOGI(acme_tag, "%s()", __FUNCTION__);
  if (account) {
    if (account->key_type) free(account->key_type);
    if (account->key_id) free(account->key_id);
    if (account->key_e) free(account->key_e);
    if (account->initialIp) free(account->initialIp);
    if (account->createdAt) free(account->createdAt);
    if (account->location) free(account->location);
    free(account);
    account = 0;
  }
}

void Acme::ClearOrderContent() {
  ESP_LOGD(acme_tag, "%s()", __FUNCTION__);
  if (order == 0) {
    order = (Order *)malloc(sizeof(Order));
    memset((void *)order, 0, sizeof(Order));
    return;
  }
  if (order->status) free(order->status);
  if (order->expires) free(order->expires);
  if (order->finalize) free(order->finalize);
  if (order->certificate) free(order->certificate);
  if (order->location) free(order->location);
  if (order->identifiers) {
    for (int i=0; order->identifiers[i]._type; i++) {
      free(order->identifiers[i]._type);
      free(order->identifiers[i].value);
    }
    free(order->identifiers);
  }
  if (order->authorizations) {
    for (int i=0; order->authorizations[i]; i++)
      free(order->authorizations[i]);
    free(order->authorizations);
  }

  memset(order, 0, sizeof(Order));
}

void Acme::ClearOrder() {
  ESP_LOGD(acme_tag, "%s()", __FUNCTION__);
  if (order) {
    ClearOrderContent();

    free(order);
    order = 0;
  }
}

void Acme::ClearChallenge() {
  if (challenge) {
    if (challenge->status) free(challenge->status);
    if (challenge->expires) free(challenge->expires);
    if (challenge->identifiers) {
      for (int i=0; challenge->identifiers[i]._type; i++) {
        free(challenge->identifiers[i]._type);
        free(challenge->identifiers[i].value);
      }
      free(challenge->identifiers);
    }
    if (challenge->challenges) {
      for (int i=0; challenge->challenges[i]._type; i++) {
        free(challenge->challenges[i]._type);
        free(challenge->challenges[i].status);
        free(challenge->challenges[i].url);
        free(challenge->challenges[i].token);
      }
      free(challenge->challenges);
    }
    free(challenge);
    challenge = 0;
  }
}

/*
 * Read from file
 */
bool Acme::ReadAccountInfo() {
  if (account_fn == 0 || filename_prefix == 0) {
    ESP_LOGE(acme_tag, "%s: ACME files not configured", __FUNCTION__);
    return false;
  }
  char *fn = (char *)malloc(strlen(account_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, account_fn);

  FILE *f = fopen(fn, "r");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could not read account info from %s, %s", fn, strerror(errno));
    free(fn);
    return false;
  }

// Choose wisely
#define	NREAD_INC	250

  // ESP-IDF VFS over SPIFFS doesn't allow use of fseek to determine file length, so read in chunks in that case
  // Potential over-allocation is limited to NREAD_INC bytes
  long len = fseek(f, 0L, SEEK_END);
  if (len == 0) {
    len = NREAD_INC;
  }
  ESP_LOGI(acme_tag, "Reading Account info from %s", fn);
  free(fn);

  fseek(f, 0L, SEEK_SET);
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
    ESP_LOGD(acme_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  ESP_LOGD(acme_tag, "%s: %s", __FUNCTION__, buffer);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, buffer);
  if (je) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(buffer);
    return false;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);
  ReadAccount(root);

  free(buffer);
  return true;
}

void Acme::WriteAccountInfo() {
  if (account == NULL) {
    ESP_LOGE(acme_tag, "%s: NULL account", __FUNCTION__);
    return;
  }

  char *fn = (char *)malloc(strlen(account_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, account_fn);
  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could not write account info into %s, %s", fn, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGI(acme_tag, "Writing account info into %s", fn);
  free(fn);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument jo(1024);
#else
  JsonDocument jo;
#endif
  jo[acme_json_status] = account->status;
  jo[acme_json_location] = account->location;

  // contact array must be NULL terminated
#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument jca = jo.createNestedArray(acme_json_contact);
#else
  JsonDocument jca = jo[acme_json_contact].to<JsonArray>();
#endif
  for (int i=0; account->contact[i]; i++)
    jca.add(account->contact[i]);

#if ARDUINOJSON_VERSION_MAJOR < 7
  JsonObject jk = jo.createNestedObject(acme_json_key);
#else
  JsonObject jk = jo[acme_json_key].to<JsonObject>();
#endif
  jk[acme_json_kty] = account->key_type;
  jk[acme_json_n] = account->key_id;
  jk[acme_json_e] = account->key_e;

  size_t sz = measureJson(jo);
  char *output = (char *)malloc(sz + 1);
  size_t nb = serializeJson(jo, output, sz+1);
  fprintf(f, "%s", output);
  fclose(f);

  ESP_LOGD(acme_tag, "Wrote %d bytes of JSON account info", nb);
  ESP_LOGD(acme_tag, "Account info : %s", output);
  free(output);
}

void Acme::RequestNewOrder(const char *url) {
  ESP_LOGI(acme_tag, "%s (%s)", __FUNCTION__, url);
  ClearOrderContent();
  ClearChallenge();
  /*
   * prot :
   *  {"alg": "RS256", "nonce": "webIkLvTEpwjbA9rZSTv8", "kid": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/0123", "url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"}
   * pl :
   *  {\n  "identifiers": [\n    {\n      "value": "to.org",\n      "type": "dns"\n    }\n  ]\n}
   * 
   * Sending POST request to https://acme-staging-v02.api.letsencrypt.org/acme/new-order:
   * {
   *   "signature": "CSrJ8AspnxgA4lq6mx43Aiwi-GJxyXw",
   *   "protected": "ovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1vcmRlciJ9",
   *   "payload": "ewiZG5zIgogICAgfQogIF0KfQ"
   * }
   * 2019-07-31 04:01:52,543:DEBUG:requests.packages.urllib3.connectionpool:https://acme-staging-v02.api.letsencrypt.org:443 "POST /acme/new-order HTTP/1.1" 201 36
   */
  if (directory == 0 || rsa == 0)
    return;

  char *msg;
  char *request = (char *)malloc(strlen(new_order_template) + strlen(url) + 4);
  sprintf(request, new_order_template, url);
  ESP_LOGD(acme_tag, "%s msg %s", __FUNCTION__, request);

  msg = MakeMessageKID(directory->newOrder, request);

  if (! msg) {
    ESP_LOGE(acme_tag, "%s: MakeMessageKID -> null message", __FUNCTION__);
    return;
  }
  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, msg);

  setQueryType(query_order);
  char *reply = PerformWebQuery(directory->newOrder, msg, acme_jose_json, 0);
  if (reply) {
    ESP_LOGD(acme_tag, "%s: PerformWebQuery -> %s", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }
  resetQueryType();

  // Decode JSON reply
#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  if (reply_status && (strcmp(reply_status, acme_status_pending) == 0)) {
    // We might just have info we want to keep
    ESP_LOGD(acme_tag, "%s: order status %s keep location %s", __FUNCTION__,
      reply_status, order->location ? order->location : "(null)");
  } else {
    ClearOrderContent();
  }

  ReadOrder(root);

  free(reply);
  return;
}

/*
 * Read from file
 */
bool Acme::ReadOrderInfo() {
  char *fn = (char *)malloc(strlen(order_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, order_fn);

  ESP_LOGI(acme_tag, "%s(fn %s)", __FUNCTION__, fn);

  FILE *f = fopen(fn, "r");
  if (f == NULL) {
    if (errno != ENOENT)	// Don't bother telling the file simply isn't there
      ESP_LOGD(acme_tag, "Could not read order info from %s, %s", fn, strerror(errno));
    free(fn);
    return false;
  } else {
    ESP_LOGI(acme_tag, "Reading order info from %s", fn);
  }

// Choose wisely
#define	NREAD_INC	250

  // ESP-IDF VFS over SPIFFS doesn't allow use of fseek to determine file length, so read in chunks in that case
  // Potential over-allocation is limited to NREAD_INC bytes
  long len = fseek(f, 0L, SEEK_END);
  if (len == 0) {
    len = NREAD_INC;
    ESP_LOGD(acme_tag, "Reading order info from %s (in chunks of %d)", fn, NREAD_INC);
  } else
    ESP_LOGD(acme_tag, "Reading order info from %s (%ld bytes)", fn, len);
  fseek(f, 0L, SEEK_SET);
  free(fn);

  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    ESP_LOGD(acme_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  buffer[total] = 0;
  ESP_LOGI(acme_tag, "%s: %s", __FUNCTION__, buffer);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, buffer);
  if (je)
  {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(buffer);
    return false;
  }

  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);
  ReadOrder(root);

  free(buffer);

  ESP_LOGD(acme_tag, "%s : success, order status %s", __FUNCTION__,
    order->status ? order->status : "?");

  // This is in an HTTP header
  if (retry_after) {
    if (order->retry_after)
      free(order->retry_after);
    order->retry_after = strdup(retry_after);
  }

  return true;
}

void Acme::WriteOrderInfo() {
  if (order == NULL) {
    ESP_LOGE(acme_tag, "%s: NULL order", __FUNCTION__);
    return;
  }

  char *fn = (char *)malloc(strlen(order_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, order_fn);
  CreateDirectories(fn);
  FILE *f = fopen(fn, "w");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Couldn't write order info into %s, %s", fn, strerror(errno));
    free(fn);
    return;
  }

  ESP_LOGD(acme_tag, "Writing order info into %s", fn);
  free(fn);

#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument jo(1024);
#else
  JsonDocument jo;
#endif

  if (order->status) jo[acme_json_status] = order->status;
  if (order->status) jo[acme_json_expires] = order->expires;
  if (order->finalize) jo[acme_json_finalize] = order->finalize;
  if (order->certificate) jo[acme_json_certificate] = order->certificate;
  if (order->location) jo[acme_json_location] = order->location;

  if (retry_after) {
    jo[acme_json_retry_after] = retry_after;
    ESP_LOGD(acme_tag, "%s (retry-after %s)", __FUNCTION__, retry_after);
  } else if (order->retry_after) {
    jo[acme_json_retry_after] = order->retry_after;
    ESP_LOGD(acme_tag, "%s (order-retry-after %s)", __FUNCTION__, order->retry_after);
  }

  if (order->identifiers) {
    // identifiers array must be NULL terminated
#if ARDUINOJSON_VERSION_MAJOR < 7
    JsonArray jia = jo.createNestedArray(acme_json_identifiers);
#else
    JsonArray jia = jo[acme_json_identifiers].to<JsonArray>();
#endif
    for (int i=0; order->identifiers[i]._type != 0 || order->identifiers[i].value != 0; i++) {
#if ARDUINOJSON_VERSION_MAJOR < 7
      JsonObject jie = jia.createNestedObject();
#else
      JsonObject jie = jia.add<JsonObject>();
#endif
      jie[acme_json_type] = order->identifiers[i]._type;
      jie[acme_json_value] = order->identifiers[i].value;

      ESP_LOGD(acme_tag, "%s: identifiers[%d] = %s %s", __FUNCTION__, i,
        order->identifiers[i]._type, order->identifiers[i].value);
    }
  }

  if (order->authorizations) {
    // authorizations array must be NULL terminated
#if ARDUINOJSON_VERSION_MAJOR < 7
    JsonArray jaa = jo.createNestedArray(acme_json_authorizations);
#else
    JsonArray jaa = jo[acme_json_authorizations].to<JsonArray>();
#endif
    for (int i=0; order->authorizations[i]; i++) {
      jaa.add(order->authorizations[i]);
      ESP_LOGD(acme_tag, "%s: authorizations[%d] = %s", __FUNCTION__, i, order->authorizations[i]);
    }
  }

  size_t sz = measureJson(jo);
  char *output = (char *)malloc(sz + 1);
  size_t nb = serializeJson(jo, output, sz+1);
  fprintf(f, "%s", output);
  fclose(f);

  ESP_LOGD(acme_tag, "Wrote %d bytes of JSON order info", nb);
  ESP_LOGD(acme_tag, "%s: Order info : %s", __FUNCTION__, output);
  free(output);
}

/*
 */
/*
Acme: setLocation(https://acme-staging-v02.api.letsencrypt.org/acme/order/130199564/13387543894) - finalize (order 0x3fccb770)
Acme: Writing order info into /fs/acme/staging/order.json
Acme: Wrote 401 bytes of JSON order info
Acme: Order info : {"status":"ready","expires":"2024-01-09T14:07:46Z","finalize":"https://acme-staging-v02.api.letsencrypt.org/acme/finalize/130199564/13387543894","location":"https://acme-staging-v02.api.letsencrypt.org/acme/order/130199564/13387543894","identifiers":[{"type":"dns","value":"waskot.dannybackx.dns-cloud.net"}],"authorizations":["https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/10259770504"]}
Acme: ReadOrder()
Acme: ClearOrder()
Acme: ClearOrderContent()
Acme: ReadOrder : read status as processing
Acme: ReadOrder : read expires as 2024-01-09T14:07:46Z
Acme: ReadOrder : read finalize as https://acme-staging-v02.api.letsencrypt.org/acme/finalize/130199564/13387543894
Acme: Writing order info into /fs/acme/staging/order.json
Acme: WriteOrderInfo (retry-after 3)
Acme: Wrote 333 bytes of JSON order info
 */
#if ARDUINOJSON_VERSION_MAJOR < 7
void Acme::ReadOrder(DynamicJsonDocument &json)
#else
void Acme::ReadOrder(JsonDocument &json)
#endif
{
  ESP_LOGI(acme_tag, "%s()", __FUNCTION__);

  // Treat the case separately where we have an empty order structure :
  // it's brand new so no need to free/reallocate
  if (order && order->status != 0)
    ClearOrder();

  AugmentOrder(json);
}

#if ARDUINOJSON_VERSION_MAJOR < 7
void Acme::AugmentOrder(DynamicJsonDocument &json)
#else
void Acme::AugmentOrder(JsonDocument &json)
#endif
{
  ESP_LOGD(acme_tag, "%s()", __FUNCTION__);

  if (order == 0) {
    order = (Order *)malloc(sizeof(Order));
    memset((void *)order, 0, sizeof(Order));
  }

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      ESP_LOGD(acme_tag, "%s : read %s as %s", __FUNCTION__, #x, x);		\
      order->x = strdup(x);							\
    } else {									\
      order->x = 0;								\
    }										\
  }

  BZZ(status);
  BZZ(expires);
  BZZ(finalize);
  BZZ(certificate);
  BZZ(retry_after);
#warning does not seem to work
  // BZZ(location);

  const char *jl = json[acme_json_location];
  // Don't overwrite if nothing in the JSON
  if (jl) {
    order->location = strdup(jl);
    ESP_LOGD(acme_tag, "%s : %s %s", __FUNCTION__, acme_json_location, jl);
  } else {
    ESP_LOGD(acme_tag, "%s : %s keep %s", __FUNCTION__, acme_json_location,
      order->location ? order->location : "(null)");
  }

  if (order->expires)
    order->t_expires = timestamp(order->expires);

#undef BZZ

  JsonArray jia = json["identifiers"];
  ESP_LOGD(acme_tag, "%s : %d identifiers", __FUNCTION__, jia.size());

  order->identifiers = (Identifier *)calloc(jia.size()+1, sizeof(Identifier));
  order->identifiers[jia.size()]._type = 0;
  order->identifiers[jia.size()].value = 0;
  for (int i=0; i<jia.size(); i++) {
    const char *it = jia[i]["type"];
    const char *iv = jia[i]["value"];
    order->identifiers[i]._type = it ? strdup(it) : 0;
    order->identifiers[i].value = iv ? strdup(iv) : 0;

    ESP_LOGD(acme_tag, "Identifiers %d - %s %s", i, it, iv);
  }

  JsonArray jaa = json["authorizations"];
  ESP_LOGD(acme_tag, "%s : %d authorizations", __FUNCTION__, jaa.size());

  order->authorizations = (char **)calloc(jia.size()+1, sizeof(char *));
  order->authorizations[jaa.size()] = 0;
  for (int i=0; i<jaa.size(); i++) {
    const char *a = jaa[i];
    order->authorizations[i] = a ? strdup(a) : 0;

    ESP_LOGD(acme_tag, "Auth %d - %s", i, a);
  }
}

// Store a file on an FTP server
return_status Acme::ValidateOrder() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  char *localfn = 0, *remotefn = 0;

  int error = DownloadAuthorizationResource();
  if (error != 0) {
    ESP_LOGE(acme_tag, "%s: status %s, change to %s", __FUNCTION__, order->status, acme_status_invalid);
    if (order->status) free(order->status);
    order->status = strdup(acme_status_invalid);
    return status_fail;
  }

  const char *token = 0;
  http01_ix = -1;
  for (int i=0; challenge && challenge->challenges && challenge->challenges[i].status; i++) {
    ESP_LOGD(acme_tag, "%s: checking challenge %d : type %s token %s", __FUNCTION__,
      i, challenge->challenges[i]._type, challenge->challenges[i].token);
    if (strcmp(challenge->challenges[i]._type, acme_http_01) == 0) {
      token = challenge->challenges[i].token;
      http01_ix = i;
      ESP_LOGD(acme_tag, "%s: HTTP challenge in %d, token %s", __FUNCTION__, i, token);
    }
  }
  if (token == 0) {
    ESP_LOGE(acme_tag, "%s: no %s token found, aborting authorization", __FUNCTION__, acme_http_01);
    return status_fail;
  }
  ESP_LOGD(acme_tag, "%s: token %s", __FUNCTION__, token);

  if (webserver) {
    /*
     * The IoT device has a local web server.
     * Either this device is "in the wild" or firewall/router/webserver tweaks have been
     * made so it is accessible from the Internet.
     */
    ValidationString = CreateValidationString(token);
    
    // The file name that should be queried is a short form of the above remotefn
    ValidationFile = (char *)malloc(strlen(well_known) + strlen(token) + 2);
    sprintf(ValidationFile, "%s%s", well_known, token);

    EnableLocalWebServer();
  } else {
#if USE_EXTERNAL_WEBSERVER
    if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
      ESP_LOGE(acme_tag, "%s: failed, incomplete FTP setup", __FUNCTION__);
      return false;
    }

    /*
     * This case uses services from a "site" web server.
     * We use FTP to store and remove files on it.
     *
     * Store the token in a file.
     * Notes : take a single file for two reasons : can't remove it (see below), and the file system
     * doesn't always support file names in the format returned by an ACME server.
     */
    localfn = (char *)malloc(strlen(filename_prefix) + 15);
    sprintf(localfn, "%s/token", filename_prefix);

    if (! CreateValidationFile(localfn, token)) {
      ESP_LOGE(acme_tag, "%s: could not create local validation file %s", __FUNCTION__, localfn);
      free(localfn);
      return false;
    }

    // FTP the file
    remotefn = (char *)malloc(strlen(ftp_path) + strlen(well_known) + strlen(token) + 5);
    sprintf(remotefn, "%s%s%s", ftp_path, well_known, token);

    StoreFileOnWebserver(localfn, remotefn);
#else
  ESP_LOGE(acme_tag, "%s: external web server not enabled", __FUNCTION__);
#endif
  }

  // Alert the server
  return_status r = ValidateAlertServer();

  // Remove the file
  if (webserver != 0) {
    if (r != status_pending) {
      if (ValidationString) {
        free(ValidationString);
        ValidationString = 0;
      }
      if (ValidationFile) {
        free(ValidationFile);
        ValidationFile = 0;
      }

      if (ws_registered)
        DisableLocalWebServer();
    }
  } else {
    /*
     * FIXME Can't find a API call (except when accessing SPIFFS) to remove a file
     * in the ESP-IDF VFS layer
     *
     * Sometimes this is too soon.
     * Leaving the challenges here makes sure we can pick this up in AcmeProcess() in case
     * of failures, only clean up on success.
     */
    if (r != status_pending) {
      // Remove the file from FTP server
      RemoveFileFromWebserver(remotefn);

      // Remove our in-memory record
      ClearChallenge();
    }

    free(remotefn);
    free(localfn);
  }
  return r;
}

/*
 * Send a request to the server to read our token
 * We're only implementing the http-01 protocol here...
 */
return_status Acme::ValidateAlertServer() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  if (http01_ix < 0) {
    ESP_LOGE(acme_tag, "%s: no %s found", __FUNCTION__, acme_http_01);
    return status_fail;
  }

  char *msg = MakeMessageKID(challenge->challenges[http01_ix].url, "{}");
  challenge->challenges[http01_ix].active = true;

  ESP_LOGD(acme_tag, "%s: query %s message %s", __FUNCTION__, challenge->challenges[http01_ix].url, msg);

  // FIXME only one authorization is picked up
  char *reply = PerformWebQuery(challenge->challenges[http01_ix].url, msg, acme_jose_json, 0);

  free(msg);
  if (reply) {
    ESP_LOGD(acme_tag, "%s: PerformWebQuery -> %s", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }

  // Decode JSON reply
#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je)
  {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return status_fail;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return status_fail;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
    free(reply);
    return status_fail;
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  free(reply);
  return_status st = ReadAuthorizationReply(root);

  return st;
}

/*
 * The default format of the certificate is application/pem-certificate-chain
 * The ACME client MAY request other formats by [..] use the media type
 * "application/pkix-cert" [RFC2585] or "application/pkcs7-mime" [RFC5751] to
 * request the end-entity certificate in DER format.
 * Server support for alternate formats is OPTIONAL.
 */
bool Acme::DownloadCertificate() {
  bool ok = true;
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, order->certificate);

  char *msg = MakeMessageKID(order->certificate, "");

  ESP_LOGD(acme_tag, "%s: PerformWebQuery(%s,%s,%s,%s)", __FUNCTION__, order->certificate, msg, acme_jose_json, acme_accept_pem_chain);

  char *reply = PerformWebQuery(order->certificate, msg, acme_jose_json, acme_accept_pem_chain);

  free(msg);
  if (reply) {
    ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
    return false;
  }

  if (ws_registered)
    DisableLocalWebServer();

  /*
   * We requested PEM so that's what we got.
   * If the caller wants DER, then the certificate file name should end with that suffix.
   * Detect that and try to convert.
   */
  size_t cert_len = strlen(reply);
  char *cert_ptr = reply;

  const char *suffix = cert_fn + strlen(cert_fn) - 3;
  if (strcasecmp(suffix, "der") == 0) {
    ESP_LOGE(acme_tag, "%s: need to convert format for writing into %s", __FUNCTION__, cert_fn);
  }

  /*
   * Ok so now actually save.
   */
  int fnl = strlen(filename_prefix) + strlen(cert_fn) + 3;
  char *fn = (char *)malloc(fnl);
  sprintf(fn, "%s/%s", filename_prefix, cert_fn);
  FILE *f = fopen(fn, "w");
  if (f) {
    size_t fl = fwrite(cert_ptr, 1, cert_len, f);
    if (fl != cert_len) {
      ESP_LOGE(acme_tag, "Failed to write certificate to %s, %d of %d written", fn, fl, cert_len);
      ok = false;
    } else {
      ESP_LOGD(acme_tag, "Wrote certificate to %s", fn);
    }
    fclose(f);
  } else {
    ESP_LOGE(acme_tag, "Could not open %s to write certificate, error %d (%s)", fn, errno, strerror(errno));
    ok = false;
  }
  free(reply);

  if (ok) ReadCertificate();
  return ok;
}

/*
 * Fetch the result of an Authorization. If valid, then we can move ahead with certificate download.
 *
 * We're not storing this info into a structure similar to the message content. Rather, we're
 * using this info to match with our existing Order structure, and update it.
 *
 * {
 *   "type": "http-01",
 *   "status": "valid",
 *   "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/28523991/ZQYjMg",
 *   "token": "XNmOzvEOv57hbpXC7kbZMEAjy1HiLT6g_opkKG7XUaY",
 *   "validationRecord": [
 *     {
 *       "url": "http://dannybackx.hopto.org/.well-known/acme-challenge/XNmOzvEOv57hbpXC7kbZMEAjy1HiLT6g_opkKG7XUaY",
 *       "hostname": "dannybackx.hopto.org",
 *       "port": "80",
 *       "addressesResolved": [
 *         "94.224.125.18"
 *       ],
 *       "addressUsed": "94.224.125.18"
 *     }
 *   ]
 * }
 *
 * Possible return values : fail, pending, ok.
 */
#if ARDUINOJSON_VERSION_MAJOR < 7
return_status Acme::ReadAuthorizationReply(DynamicJsonDocument &json)
#else
return_status Acme::ReadAuthorizationReply(JsonDocument &json)
#endif
{
  const char *status = json[acme_json_status];
  if (status == 0) {
    ESP_LOGI(acme_tag, "Acme::%s status (null)", __FUNCTION__);
    return status_fail;
  }
  ESP_LOGD(acme_tag, "Acme::%s status %s", __FUNCTION__, status);

#if 0
  // Only accepts "valid"
  if (strcmp(status, acme_status_valid) != 0) {
    ESP_LOGE(acme_tag, "Acme::%s invalid status (%s), returning", __FUNCTION__, status);
    return status_fail;
  }

  free(order->status);
  order->status = strdup(acme_status_ready);	// Important note : advancing our local order to "ready"
  ESP_LOGD(acme_tag, "Acme::%s WriteOrderInfo() status %s", __FUNCTION__, order->status);
  WriteOrderInfo();
  return status_ok;
#else
  // Accept either valid or pending
  if (strcmp(status, acme_status_valid) == 0) {
    free(order->status);
    order->status = strdup(acme_status_ready);	// Important note : advancing our local order to "ready"
    ESP_LOGD(acme_tag, "Acme::%s WriteOrderInfo() status %s", __FUNCTION__, order->status);
    WriteOrderInfo();
    return status_ok;
  }
  if (strcmp(status, acme_status_pending) == 0) {
    free(order->status);
    order->status = strdup(status);
    ESP_LOGD(acme_tag, "Acme::%s WriteOrderInfo() status %s", __FUNCTION__, order->status);
    WriteOrderInfo();
    return status_pending;
  }
  ESP_LOGE(acme_tag, "Acme::%s invalid status (%s), returning", __FUNCTION__, status);
  return status_fail;
#endif
}

/*
 * Download Authorization Resource
 * See RFC 8555 §7.5
 *
 * This is the file that we'll need to make a available on a WWW server to authenticate our connection to the domain.
 *
 *  POST /acme/authz/PAniVnsZcis HTTP/1.1
 *    Host: example.com
 *    Content-Type: application/jose+json
 * 
 *    {
 *      "protected": base64url({
 *        "alg": "ES256",
 *        "kid": "https://example.com/acme/acct/evOfKhNU60wg",
 *        "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
 *        "url": "https://example.com/acme/authz/PAniVnsZcis"
 *      }),
 *      "payload": "",
 *      "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
 *    }
 */
int Acme::DownloadAuthorizationResource() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  if (order == 0 || order->authorizations == 0 || order->authorizations[0] == 0) {
    ESP_LOGE(acme_tag, "%s: null", __FUNCTION__);
    return -1;
  }

  // Loop over authorizations, one at a time
  for (int i=0; order->authorizations[i]; i++) {
    ESP_LOGD(acme_tag, "%s: %d %s", __FUNCTION__, i, order->authorizations[i]);

    char *msg = MakeMessageKID(order->authorizations[i], "");

    ESP_LOGD(acme_tag, "%s: query %s message %s", __FUNCTION__, order->authorizations[i], msg);

    char *reply = PerformWebQuery(order->authorizations[i], msg, acme_jose_json, 0);

    free(msg);
    if (reply) {
      ESP_LOGD(acme_tag, "PerformWebQuery -> %s", reply);
    } else {
      ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
    }

    // Decode JSON reply
#if ARDUINOJSON_VERSION_MAJOR < 7
    DynamicJsonDocument root(512);
#else
    JsonDocument root;
#endif
    DeserializationError je = deserializeJson(root, reply);
    if (je) {
      ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
      free(reply);
      return -1;
    }
    ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

    const char *reply_status = root[acme_json_status];
    if (reply_status && reply_status[0] == '4') {
      const char *reply_type = root[acme_json_type];
      const char *reply_detail = root[acme_json_detail];

      ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

      free(reply);
      int reply_status_num = root[acme_json_status];
      return reply_status_num;
    } else if (reply_status == 0) {
      // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
      ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
      return -1;
    } else {
      ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
    }

    ReadChallenge(root);
    free(reply);
  }
  return 0;
}

/*
 * RFC 7638 describes the JSON Web Key (JWK) Thumbprint
 */
char *Acme::JWSThumbprint() {
  int err;

  int ne = 4;						// E will be at the rear end of this array
  unsigned char	E[4];
  int nl = mbedtls_rsa_get_len(rsa);
  unsigned char *N = (unsigned char *)malloc(nl);	// Allocate exactly long enough, don't add one more for trailing 0.

  if ((err = mbedtls_rsa_export_raw(rsa, N, nl, /* P */ 0, 0, /* Q */ 0, 0, /* D */ 0, 0, E, ne)) != 0) {
    char buf[80];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: failed rsa_export_raw %d %s", __FUNCTION__, err, buf);
    return 0;
  }

  // E is at the rear end of this array, point q to it
  char *q = (char *)E;
  for (; *q == 0; q++,ne--);			// Skip initial zeroes

  char *n64 = Base64((char *)N, nl);
  char *e64 = Base64((char *)q, ne);
  ESP_LOGD(acme_tag, "RSA key E(64) : %s, N(64) : %s", e64, n64);

  // White-space-less JWK format, as described.
  // Don't change this even a little bit
  const char *format = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";

  char *t = (char *)malloc(strlen(format) + 2 * nl + ne + 4);		// hack : 2*, otherwise crash due to alloc(280), but use 370
  sprintf(t, format, e64, n64);
  free(N);
  free(n64);
  free(e64);

  int hash_size = 32;
  unsigned char *hash = (unsigned char *)calloc(1, hash_size);
  if (hash == 0) {
    ESP_LOGE(acme_tag, "calloc(32) failed");
    free(t);
    return 0;
  }

  const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mdi) {
    ESP_LOGE("Acme", "mbedtls_md_info_from_type: md_info not found");
    free(hash);
    free(t);
    return 0;
  }

  int ret = mbedtls_md(mdi, (const unsigned char *)t, strlen(t), (unsigned char *)hash);
  free(t); t = 0;
  if (ret != 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "mbedtls_md failed %s (0x%04x)", buf, -ret);
    free(hash);
    return 0;
  }

  char *r = Base64((char *)hash, hash_size);
  free(hash);
  return r;
}

// Create it locally
bool Acme::CreateValidationFile(const char *localfn, const char *token) {
  FILE *tf = fopen(localfn, "w");
  if (! tf) {
    ESP_LOGE(acme_tag, "%s: could not create %s, %s", __FUNCTION__, localfn, strerror(errno));
    return false;
  }

  char *tp = JWSThumbprint();
  fprintf(tf, "%s.%s\n", token, tp);
  free(tp);

  fclose(tf);
  return true;
}

// For use by the local web server
char *Acme::CreateValidationString(const char *token) {
  char *tp = JWSThumbprint();
  int len = strlen(token) + strlen(tp) + 4;
  char *r = (char *)malloc(len);
  sprintf(r, "%s.%s\n", token, tp);
  return r;					// Caller must free
}

#if ARDUINOJSON_VERSION_MAJOR < 7
void Acme::ReadChallenge(DynamicJsonDocument &json)
#else
void Acme::ReadChallenge(JsonDocument &json)
#endif
{
  challenge = (Challenge *)malloc(sizeof(Challenge));
  memset((void *)challenge, 0, sizeof(Challenge));

/*
 * Replace a single statement such as
 *   account->key_type = strdup(json["key"]["kty"]);
 * by a macro invocation to protect against calling strdup(0) if an element is not in the JSON.
 * C/C++ syntax hint : #x turns the macro argument x into a string.
 */
#define	BZZ(x)									\
  {										\
    const char *x = json[#x];							\
    if (x) {									\
      ESP_LOGD(acme_tag, "%s : read %s as %s", __FUNCTION__, #x, x);		\
      challenge->x = strdup(x);							\
    } else {									\
      challenge->x = 0;								\
    }										\
  }

  BZZ(status);
  BZZ(expires);

  challenge->t_expires = timestamp(challenge->expires);

#undef BZZ

  // we're not reading the identifier, as we're not using it
  JsonArray jca = json["challenges"];
  ESP_LOGD(acme_tag, "%s : %d challenges", __FUNCTION__, jca.size());

  challenge->challenges = (ChallengeItem *)calloc(jca.size()+1, sizeof(ChallengeItem));
  // Null-terminate
  challenge->challenges[jca.size()]._type = 0;
  challenge->challenges[jca.size()].status = 0;
  challenge->challenges[jca.size()].url = 0;
  challenge->challenges[jca.size()].token = 0;
  for (int i=0; i<jca.size(); i++) {
    const char *ct = jca[i][acme_json_type];
    const char *cs = jca[i][acme_json_status];
    const char *cu = jca[i][acme_json_url];
    const char *ck = jca[i][acme_json_token];

    challenge->challenges[i]._type = strdup(ct);
    challenge->challenges[i].status = strdup(cs);
    challenge->challenges[i].url = strdup(cu);
    if (ck == NULL)
        ESP_LOGE(acme_tag, "!!! ERROR func '%s' in challenge %d of %d 'acme_json_token' == NULL", __FUNCTION__, i + 1, jca.size());
    challenge->challenges[i].token = (ck) ? strdup(ck) : NULL;
    challenge->challenges[i].active = false;	// new, internal
  }
}

/*
 * Make an ACME message, this version makes the ones that include a "kid" field.
 *
 * Some of the relevant parts of RFC 8555 (§6.2) :
 *   It must have the fields "alg", "nonce", "url", and either "jwk" or "kid".
 *   newAccount and revokeCert messages must use jwk, this field must contain the public key
 *   corresponding to the private key used to sign the JWS.
 *   All other requests are signed using an existing account, and there must be a kid field
 *   which contains the account URL received by POSTing to newAcount.
 *
 * So this must be used in calls to RequestNewOrder, ... .
 * but especially not in calls to newAccount or revokeCert.
 *
 * {"url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct", "jwk": {"kty": "RSA",
 *  "n": "...", "e": "AQAB"}, "alg": "RS256", "nonce": "U8b_2ZGRATuySa9yPOF3JDN4JXTyEdAfrL--WTzqYKQ"}
 */
char *Acme::MakeMessageKID(const char *url, const char *payload) {
  ESP_LOGD(acme_tag, "%s(%s,%s)", __FUNCTION__, url, payload);

  char *prot = MakeProtectedKID(url);
  if (prot == 0) {
    ESP_LOGD(acme_tag, "%s: MakeProtectedKID -> null", __FUNCTION__);
    return 0;
  }

  ESP_LOGD(acme_tag, "PR %s", prot);
  char *pr = Base64(prot);
  char *pl = Base64(payload);
  char *sig = Signature(pr, pl);

  char *js = 0;
  int sz = 0;

  // "{\n  \"protected\": \"%s\",\n  \"payload\": \"%s\",\n  \"signature\": \"%s\"\n}",
  sz = snprintf(js, sz, acme_message_kid_template, pr, pl, sig);
  if (sz < 0)
    return 0;
  sz++;
  js = (char *)malloc(sz);
  snprintf(js, sz, acme_message_kid_template, pr, pl, sig);
  free(prot);
  free(pr);
  free(pl);
  free(sig);

  return js;
}

void Acme::SetAcmeUserAgentHeader(esp_http_client_handle_t client) {
  int err;

  char *acme_agent_value = (char *)malloc(strlen(acme_agent_template) + strlen(esp_get_idf_version()) + 10);
  sprintf(acme_agent_value, acme_agent_template, esp_get_idf_version());
  if ((err = esp_http_client_set_header(client, acme_agent_header, acme_agent_value)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_agent_header, acme_agent_value, err, esp_err_to_name(err));
    // Don't fail on this.
  } else {
    ESP_LOGD(acme_tag, "%s: client_set_header(%s=%s)", __FUNCTION__, acme_agent_header, acme_agent_value);
  }
  free(acme_agent_value);
}

/*
 * This will be the protected field in the JSON
 *
 * {"alg": "RS256", "nonce": "webISTv8", "kid": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/012", "url": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"}
 */
char *Acme::MakeProtectedKID(const char *query) {
  if (account->location == 0)
    ESP_LOGE(acme_tag, "%s: location null", __FUNCTION__);
  if (nonce == 0)
    ESP_LOGE(acme_tag, "%s: nonce null", __FUNCTION__);
  if (account->location == 0 || nonce == 0)
    return 0;

  char *my_nonce = GetNonce();
  ESP_LOGD(acme_tag, "%s use nonce %s", __FUNCTION__, my_nonce);
  if (my_nonce == 0)
    return 0;

  const char *acme_protected_template = "{\"alg\": \"RS256\", \"nonce\": \"%s\", \"url\": \"%s\", \"kid\": \"%s\"}";
  char *request = (char *)malloc(strlen(acme_protected_template) + strlen(query) + strlen(my_nonce) + strlen(account->location) + 4);
  sprintf(request, acme_protected_template, my_nonce, query, account->location);

  return request;
}

/*
 * Perform a query
 *
 * Post the topost data.
 */
char *Acme::PerformWebQuery(const char *query, const char *topost, const char *apptype, const char *accept_message) {
  esp_err_t			err;
  esp_http_client_config_t	httpc;
  esp_http_client_handle_t	client;
  char				*buf;
  int				pos, total, rlen, content_length;

  // Short version
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, query);
  // Long version
  ESP_LOGD(acme_tag, "%s(%s, POST %s, type %s)", __FUNCTION__, query,
    topost ? topost : "null",
    apptype ? apptype : "null");

  memset(&httpc, 0, sizeof(httpc));
  httpc.url = query;
  httpc.event_handler = HttpEvent;
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
  httpc.crt_bundle_attach = esp_crt_bundle_attach;
#else
  if (root_certificate)
    httpc.cert_pem = root_certificate;	// Required in esp-idf 4.3 for https
#endif

  // Work around esp-idf esp_http_client bug that reappeared
  httpc.buffer_size = 2048;

  client = esp_http_client_init(&httpc);

  clearQueryHeaders();
  if (reply_buffer)
    free(reply_buffer);
  reply_buffer = 0;
  reply_buffer_len = 0;

  if (topost) {
    err = esp_http_client_set_post_field(client, topost, strlen(topost));
    if (err != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: set_post_field error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    } else
      ESP_LOGD(acme_tag, "%s: set_post_field %s length %d", __FUNCTION__, topost, strlen(topost));

    // Do a POST query if we're posting data.
    if ((err = esp_http_client_set_method(client, HTTP_METHOD_POST)) != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_set_method error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
  }

  SetAcmeUserAgentHeader(client);

  const char *at = apptype ? apptype : "application/json";
  if ((err = esp_http_client_set_header(client, acme_content_type, at)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_content_type, at, err, esp_err_to_name(err));
    // Don't fail on this.
  } else {
    ESP_LOGD(acme_tag, "Client_set_header(%s=%s)", acme_content_type, at);
  }

  // When this parameter is supplied, the "Accept:" is implied
  if (accept_message) {
    if ((err = esp_http_client_set_header(client, acme_accept_header, accept_message)) != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_set_header(%s=%s) error %d %s", __FUNCTION__, acme_accept_header, accept_message, err, esp_err_to_name(err));
      // Don't fail on this.
    } else {
      ESP_LOGD(acme_tag, "Client_set_header(%s=%s)", acme_accept_header, accept_message);
    }
  }

  if (topost) {
    // Need to use esp_http_client_perform() because esp_http_client_open() doesn't call esp_http_client_send_post_data() and
    // that's a static function so we can't call it ourselves.
    err = esp_http_client_perform(client);

    // Ok, now the data has been captured in Acme::HttpEvent, just pass it on and finish up.
    ESP_LOGD(acme_tag, "%s -> %*s", __FUNCTION__, reply_buffer_len, reply_buffer);

    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    // Buffer will get freed after this, so lose its length indication
    reply_buffer_len = 0;
    char *tmp = reply_buffer;
    reply_buffer = 0;

    return tmp;
  } else {
    err = esp_http_client_open(client, 0);
    ESP_LOGD(acme_tag, "%s: esp_http_client_open -> %d %s", __FUNCTION__, err, esp_err_to_name(err));

    if (err != ESP_OK) {
      ESP_LOGE(acme_tag, "%s: client_open error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    if ((content_length = esp_http_client_fetch_headers(client)) < 0) {
      ESP_LOGE(acme_tag, "%s: fetch_headers error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    buf = (char *)malloc(content_length + 1);
    if (buf == 0) {
      ESP_LOGE(acme_tag, "%s: malloc error %d %s", __FUNCTION__, err, esp_err_to_name(err));
      esp_http_client_cleanup(client);
      return 0;
    }
    pos = 0; total = 0; rlen = 0;
    while (total < content_length && err == ESP_OK) {
      rlen = esp_http_client_read(client, buf + pos, content_length - total);
      if (rlen < 0) {
        ESP_LOGE(acme_tag, "%s: read error %d %s", __FUNCTION__, err, esp_err_to_name(err));
        free(buf);
        esp_http_client_cleanup(client);
        return 0;
      }
      buf[rlen] = 0;
      pos += rlen;
      total += rlen;
    }
  }

  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, buf);

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  return buf;
}

/*
 * This function catches HTTP headers (two of which we trap), and data sent to us as replies.
 * We gatter the latter in the reply_buffer field, whose alloc/free is rather sensitive.
 */
esp_err_t Acme::HttpEvent(esp_http_client_event_t *event) {
  switch (event->event_id) {
  case HTTP_EVENT_ON_HEADER:
    ESP_LOGD("Acme", "%s: hdr %s val %s", __FUNCTION__, event->header_key, event->header_value);
    if (strcmp(event->header_key, acme_nonce_header) == 0)
      _acme->setNonce(event->header_value);
    else if (strcmp(event->header_key, acme_location_header) == 0)
      _acme->setLocation(event->header_value);
    else if (strcmp(event->header_key, acme_retry_after_header) == 0)
      _acme->setRetryAfter(event->header_value);
    break;
  case HTTP_EVENT_ON_DATA:
    ESP_LOGD("Acme", "%s HTTP_EVENT_ON_DATA (len %d)", __FUNCTION__, event->data_len);
    if (_acme->reply_buffer_len == 0) {
      _acme->reply_buffer_len = event->data_len;
      _acme->reply_buffer = (char *)malloc(event->data_len + 1);
      strncpy(_acme->reply_buffer, (const char *)event->data, event->data_len);
      _acme->reply_buffer[event->data_len] = 0;
    } else {
      int oldlen = _acme->reply_buffer_len;

      _acme->reply_buffer_len += event->data_len;
      _acme->reply_buffer = (char *)realloc(_acme->reply_buffer, _acme->reply_buffer_len + 1);
      strncpy(_acme->reply_buffer + oldlen, (const char *)event->data, event->data_len);
      _acme->reply_buffer[_acme->reply_buffer_len] = 0;
    }
    break;
  case HTTP_EVENT_ON_FINISH:
    ESP_LOGD("Acme", "%s: received %s", __FUNCTION__, _acme->reply_buffer);
    break;
  default:
    break;
  }
  return ESP_OK;
}

/*
 * We're using https://github.com/JohnnyB1290/ESP32-FTP-Client .
 * This is a port of FTPlib (https://nbpfaus.net/~pfau/ftplib/)
 * Docs see https://nbpfaus.net/~pfau/ftplib/ftplib.html
 *
 * Note web server settings need to allow read access to these files.
 * In some cases, adding "-u 002" to the ftpd command helps in setting its umask so this works.
 *
 * Example : such a line in /etc/inetd.conf :
 * ftp     stream  tcp6    nowait  root    /usr/sbin/ftpd  ftpd -u 002
 *
 */
void Acme::StoreFileOnWebserver(char *localfn, char *remotefn) {
#if USE_EXTERNAL_WEBSERVER
  NetBuf_t	*nb = 0;

  if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
    ESP_LOGE(acme_tag, "%s: failed, incomplete setup", __FUNCTION__);
    return;
  }
  ESP_LOGD(acme_tag, "%s(%s,%s)", __FUNCTION__, localfn, remotefn);

  FtpClient	*ftpc = getFtpClient();
  ftpc->ftpClientConnect(ftp_server, 21, &nb);
  ftpc->ftpClientLogin(ftp_user, ftp_pass, nb);
  if (remotefn[0] != '/') {
    int len = strlen(remotefn) + strlen(ftp_path) + 4;
    char *b = (char *)malloc(len);
    sprintf(b, "%s/%s", ftp_path, remotefn);
    ftpc->ftpClientPut(localfn, b, FTP_CLIENT_BINARY, nb);
    free(b);
  } else {
    ftpc->ftpClientPut(localfn, remotefn, FTP_CLIENT_BINARY, nb);
  }
  ftpc->ftpClientQuit(nb);
#endif
}

void Acme::RemoveFileFromWebserver(char *remotefn) {
#if USE_EXTERNAL_WEBSERVER
  NetBuf_t	*nb = 0;

  if (! (ftp_user && ftp_path && ftp_server && ftp_pass)) {
    ESP_LOGE(acme_tag, "%s: failed, incomplete setup", __FUNCTION__);
    return;
  }
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, remotefn);

  FtpClient	*ftpc = getFtpClient();
  ftpc->ftpClientConnect(ftp_server, 21, &nb);
  ftpc->ftpClientLogin(ftp_user, ftp_pass, nb);
  if (remotefn[0] != '/') {
    int len = strlen(remotefn) + strlen(ftp_path) + 4;
    char *b = (char *)malloc(len);
    sprintf(b, "%s/%s", ftp_path, remotefn);
    ftpc->ftpClientDelete(b, nb);
    free(b);
  } else {
    ftpc->ftpClientDelete(remotefn, nb);
  }
  ftpc->ftpClientQuit(nb);
#endif
}

void Acme::OrderRemove() {
  ESP_LOGD(acme_tag, "%s()", __FUNCTION__);
  ClearOrder();

  if (order_fn == 0 || filename_prefix == 0)
    return;

  char *fn;
  if (asprintf(&fn, "%s/%s", filename_prefix, order_fn) < 0)
    return;
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, fn);

  int err = unlink(fn);
  if (err == ESP_OK)
    ESP_LOGD(acme_tag, "Removed %s", fn);
  else
    ESP_LOGE(acme_tag, "Failed to remove %s", fn);
  free((void *)fn);
}

void Acme::CertificateDownload() {
  DownloadCertificate();
}

/*
 * Create an ASN1 representation of the list of alternative URLs.
 *
 * See https://github.com/ARMmbed/mbedtls/issues/1878
 */
int Acme::CreateAltUrlList(mbedtls_x509write_csr req) {
  int l = 20;
  int ret;

  for (int i=0; alt_urls[i]; i++) {
    l += strlen(alt_urls[i]) + 20;
  }
  unsigned char *buf = (unsigned char *)malloc(l), *p = buf + l;

  int len = 0;
  for (int i=0; alt_urls[i]; i++) {
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf, (const unsigned char *)alt_urls[i], strlen(alt_urls[i])));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, strlen(alt_urls[i])));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2));
  }

  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

  if ((ret = mbedtls_x509write_csr_set_extension(&req,
        MBEDTLS_OID_SUBJECT_ALT_NAME, MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
	0,	// Critical
	(const unsigned char *)p, len)) != 0) {
    char errbuf[80];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    ESP_LOGE(acme_tag, "%s: mbedtls_x509write_csr_set_extension failed %s (0x%04x)", __FUNCTION__, errbuf, -ret);
  }

  free(buf);
  ESP_LOGD(acme_tag, "%s: ret %d", __FUNCTION__, ret);
  return ret;
}

/*
 * A Certificate Signing Request (CSR) is a required parameter to the Finalize query.
 * It can be used to add administrative data to the process, and is validated thoroughly.
 * One such additional parameter is the domain private key.
 */
char *Acme::GenerateCSR() {
  const int buflen = 4096;	// This is used in mbedtls_x509 functions internally
  int ret;

  ESP_LOGI(acme_tag, "%s()", __FUNCTION__);

  mbedtls_x509write_csr	req;
  memset(&req, 0, sizeof(req));
  mbedtls_x509write_csr_init(&req);

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
  // mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);	// Not set by default
  mbedtls_x509write_csr_set_key(&req, certkey);

  // Specify our URL, as the "common name" field.
  int snlen = strlen(acme_url) + 4;
  char *sn = (char *)malloc(snlen);
  sprintf(sn, "CN=%s", acme_url);
  ret = mbedtls_x509write_csr_set_subject_name(&req, sn);
  if (ret != 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_x509write_csr_set_subject_name failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    mbedtls_x509write_csr_free(&req);
    free(sn);
    return 0;
  }

  if (alt_urls) {
    ret = CreateAltUrlList(req);
    if (ret != 0) {
      char buf[80];
      mbedtls_strerror(ret, buf, sizeof(buf));
      ESP_LOGE(acme_tag, "%s: CreateAltUrlList failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    }
  }

  unsigned char *buffer = (unsigned char *)malloc(buflen);
  memset(buffer, 0, buflen);

  // RFC 8555 §7.4 says write in (base64url-encoded) DER format
  int len = mbedtls_x509write_csr_der(&req, buffer, buflen, mbedtls_ctr_drbg_random, ctr_drbg);
  if (len < 0) {
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: mbedtls_x509write_csr_der failed %s (0x%04x)", __FUNCTION__, buf, -ret);
    mbedtls_x509write_csr_free(&req);
    free((void *)buffer);
    free(sn);
    return 0;
  }

  // output is written at the end of the buffer, so point to it
  char *p = ((char *)buffer) + buflen - len;
  char *csr = Base64(p, len);

  free((void *)buffer);
  free(sn);
  mbedtls_x509write_csr_free(&req);

  return csr;
}

/*
 * Move the Order from "ready" to "pending" or "valid" state.
 *
 * This step requires passing the CSR, and will cause the ACME server to generate a certificate.
 * One of the results of this query is a URL for the certificate, which we can then use to download it.
 *
 * We're calling ReadFinalizeReply() at the end, but this is the same as ReadOrder().
 */
void Acme::FinalizeOrder() {
  if (order == 0 || order->finalize == 0) {
    ESP_LOGE(acme_tag, "%s: null", __FUNCTION__);
    return;
  }
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, order->finalize);

  if (certkey == 0) {
    ReadCertKey();
    if (certkey == 0) {
      ESP_LOGE(acme_tag, "%s: can't proceed without certificate private key", __FUNCTION__);
      return;
    }
  }

  char *csr = GenerateCSR();
  int csrlen = strlen(csr) + strlen(csr_format) + 5;
  char *csr_param = (char *)malloc(csrlen);
  sprintf(csr_param, csr_format, csr);
  free(csr);
  char *msg = MakeMessageKID(order->finalize, csr_param);
  ESP_LOGD(acme_tag, "%s : msg %s", __FUNCTION__, msg);

  setQueryType(query_finalize);
  char *reply = PerformWebQuery(order->finalize, msg, acme_jose_json, 0);
  free(csr_param);
  free(msg);
  if (reply) {
    ESP_LOGD(acme_tag, "%s: PerformWebQuery -> %s", __FUNCTION__, reply);
  } else {
    ESP_LOGE(acme_tag, "%s: PerformWebQuery -> null", __FUNCTION__);
  }
  resetQueryType();

  // Decode JSON reply
#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(1024);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  /*
   * ArduinoJson and LetsEncrypt strangeness.
   * Example reply :
   *   {
   *     "type": "urn:ietf:params:acme:error:orderNotReady",
   *     "detail": "Order's status (\"valid\") is not acceptable for finalization",
   *     "status": 403
   *   }
   * Apparently no double-quotes around the status reply cause conversion to const char * to fail,
   * both with and without an explicit cast.
   * So these both fail (null pointer) on the JSON example above :
   *    const char *reply_status = root[acme_json_status].as<const char *>();
   *    const char *reply_status = root[acme_json_status];
   */
  const char *reply_status = root[acme_json_status];
  const char *reply_type = root[acme_json_type];
  const char *reply_detail = root[acme_json_detail];
  if (reply_status == 0) {
    const int reply_status_num = root[acme_json_status];

    if ((reply_status_num / 100) == 4) {
      ESP_LOGE(acme_tag, "%s: failure %s %s", __FUNCTION__, reply_type, reply_detail);

      free(reply);
      return;
    } else if ((reply_status_num / 100) == 1) {
      ESP_LOGE(acme_tag, "%s untreated case - HTTP reply %3d", __FUNCTION__, reply_status_num);
      ESP_LOGE(acme_tag, "%s reply %s - %s", __FUNCTION__, reply_type, reply_detail);
      free(reply);
      return;
    }
  }

  ReadFinalizeReply(root);
  free(reply);
}

#if ARDUINOJSON_VERSION_MAJOR < 7
void Acme::ReadFinalizeReply(DynamicJsonDocument &json)
#else
void Acme::ReadFinalizeReply(JsonDocument &json)
#endif
{
  ESP_LOGD(acme_tag, "%s", __FUNCTION__);
  // ReadOrder(json);
  AugmentOrder(json);
}

/*
 * Run a POST-as-GET as described in RFC 8555 §6.3, §7.1.2.1, §7.4 .
 * We should query the order->location URL.
 *
 * If a client wishes to fetch a resource from the server (which would
 * otherwise be done with a GET), then it MUST send a POST request with
 * a JWS body as described above, where the payload of the JWS is a
 * zero-length octet string.  In other words, the "payload" field of the
 * JWS object MUST be present and set to the empty string ("").
 *
 * We will refer to these as "POST-as-GET" requests.  On receiving a
 * request with a zero-length (and thus non-JSON) payload, the server
 * MUST authenticate the sender and verify any access control rules.
 * Otherwise, the server MUST treat this request as having the same
 * semantics as a GET request for the same resource.
 */
void Acme::GetOrderStatus() {
  if (directory == 0 || order == 0 || order->location == 0) {
    ESP_LOGE(acme_tag, "%s null", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s dir %p order %p location %p", __FUNCTION__, directory, order, order ? order->location : 0);
    return;
  }
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);

  char *msg = MakeMessageKID(order->location, "");
  if (! msg) {
    ESP_LOGE(acme_tag, "%s: MakeMessageKID -> null message", __FUNCTION__);
    return;
  }
  ESP_LOGD(acme_tag, "%s -> %s", __FUNCTION__, msg);

  char *reply = PerformWebQuery(order->location, msg, acme_jose_json, 0);
  if (reply) {
    ESP_LOGD(acme_tag, "PerformWebQuery -> %s", reply);
  } else {
    ESP_LOGE(acme_tag, "PerformWebQuery -> null");
  }

  // Decode JSON reply
#if ARDUINOJSON_VERSION_MAJOR < 7
  DynamicJsonDocument root(512);
#else
  JsonDocument root;
#endif
  DeserializationError je = deserializeJson(root, reply);
  if (je) {
    ESP_LOGE(acme_tag, "%s : could not parse JSON", __FUNCTION__);
    free(reply);
    return;
  }
  ESP_LOGD(acme_tag, "%s : JSON opened", __FUNCTION__);

  const char *reply_status = root[acme_json_status];
  if (reply_status && reply_status[0] == '4') {
    const char *reply_type = root[acme_json_type];
    const char *reply_detail = root[acme_json_detail];

    ESP_LOGE(acme_tag, "%s: failure %s %s %s", __FUNCTION__, reply_status, reply_type, reply_detail);

    free(reply);
    return;
  } else if (reply_status == 0) {
    // ESP_LOGE(acme_tag, "%s: null reply_status", __FUNCTION__);
    ESP_LOGE(acme_tag, "%s: null reply_status (reply %s)", __FUNCTION__, reply);
  } else {
    ESP_LOGD(acme_tag, "%s: reply_status %s", __FUNCTION__, reply_status);
  }

  // Integrate new info
  ESP_LOGD(acme_tag, "%s : call ReadOrder()", __FUNCTION__);
  // ReadOrder(root);
  AugmentOrder(root);
  free(reply);
}

/*
 * Convert timestamp from ACME (e.g. 2019-11-25T16:56:52Z) into time_t.
 */
time_t Acme::timestamp(const char *ts) {
  const char *acme_timestamp = "%FT%TZ";
  struct tm tms;
  char *r = strptime(ts, acme_timestamp, &tms);
  if (r == 0 || *r != 0)
    return 0;	// Failed to scan
  return mktime(&tms);
}

/*
 * Read the certificate on local storage
 */
void Acme::ReadCertificate() {
  if (filename_prefix == 0 || cert_fn == 0) {
    ESP_LOGE(acme_tag, "%s fail, no file name", __FUNCTION__);
    return;
  }

  int fnl = strlen(filename_prefix) + strlen(cert_fn) + 3;
  char *fn = (char *)malloc(fnl);
  sprintf(fn, "%s/%s", filename_prefix, cert_fn);

  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, fn);

  certificate = (mbedtls_x509_crt *)calloc(1, sizeof(mbedtls_x509_crt));
  mbedtls_x509_crt_init(certificate);
  int ret = mbedtls_x509_crt_parse_file(certificate, fn);
  if (ret == 0) {
    ESP_LOGI(acme_tag, "%s: we have a certificate in %s", __FUNCTION__, fn);
    ESP_LOGI(acme_tag, "Valid from %04d-%02d-%02d %02d:%02d:%02d to %04d-%02d-%02d %02d:%02d:%02d",
      certificate->valid_from.year, certificate->valid_from.mon, certificate->valid_from.day,
      certificate->valid_from.hour, certificate->valid_from.min, certificate->valid_from.sec,
      certificate->valid_to.year, certificate->valid_to.mon, certificate->valid_to.day,
      certificate->valid_to.hour, certificate->valid_to.min, certificate->valid_to.sec);
    free(fn);
    return;
  }

  if (ret != MBEDTLS_ERR_PK_FILE_IO_ERROR) {	/* Only print unexpected errors, a non-existing certificate file isn't. */
    char buf[80];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(acme_tag, "%s: could not read certificate from %s (error 0x%04x, %s)", __FUNCTION__, fn, -ret, buf);
  }
  mbedtls_x509_crt_free(certificate);
  free(certificate);
  certificate = 0;

  free(fn);
}

bool Acme::HaveValidCertificate() {
  struct timeval now;
  gettimeofday(&now, 0);

  return HaveValidCertificate(now.tv_sec);
}

bool Acme::HaveValidCertificate(time_t now) {
  if (certificate == 0)
    return false;
  if (now < 1000)
    return true;	// No false alarms based on invalid time

  // Check date ranges
  time_t vf = TimeMbedToTimestamp(certificate->valid_from);
  if (now < vf) {
    ESP_LOGE(acme_tag, "Certificate is not valid yet");
    return false;
  }

  time_t vt = TimeMbedToTimestamp(certificate->valid_to);
  if (vt < now) {
    ESP_LOGI(acme_tag, "Certificate has expired");
    return false;
  }

  return true;
}

/*
 * Convert from mbedtls_x509_time to time_t
 * FIX ME not sure if the hour is right
 */
time_t Acme::TimeMbedToTimestamp(mbedtls_x509_time t) {
  struct tm tms;
  tms.tm_year = t.year - 1900;
  tms.tm_mon = t.mon - 1;
  tms.tm_mday = t.day;
  tms.tm_hour = t.hour;
  tms.tm_min = t.min;
  tms.tm_sec = t.sec;
  tms.tm_isdst = false;

  return mktime(&tms);
}

/*
 * RFC 8555 §7.4.2 :
 *  If the client wishes to obtain a renewed certificate, the client initiates a new order process to request one.
 *
 * This implies that we reuse existing code, but make sure that it can work while we have an existing certificate,
 * and replacing the old with the new only happens when the new certificate is successfully downloaded.
 */
void Acme::RenewCertificate() {
  ESP_LOGI(acme_tag, "%s", __FUNCTION__);
  CreateNewOrder();
  WriteOrderInfo();
}

mbedtls_x509_crt *Acme::getCertificate() {
  return certificate;
}

void Acme::setUrl(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  acme_url = fn;
}

void Acme::setAltUrl(const int ix, const char *fn) {
  if (alt_urls == 0) {
    alt_urls = (const char **)calloc(sizeof(char *), 4);
    alt_url_cnt = 4;
  }
  if (alt_url_cnt < ix + 1) {
    alt_url_cnt = ix + 4;
    alt_urls = (const char **)realloc(alt_urls, alt_url_cnt * sizeof(char *));
  }
  alt_urls[ix] = fn;
  alt_urls[ix+1] = NULL;
}

void Acme::setEmail(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  email_address = fn;
}

void Acme::setAcmeServer(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  acme_server_url = fn;
}

void Acme::setAccountFilename(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  account_fn = fn;
}

void Acme::setAccountKeyFilename(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  account_key_fn = fn;
}

void Acme::setOrderFilename(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  order_fn = fn;
}

void Acme::setCertKeyFilename(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  cert_key_fn = fn;
}

const char *Acme::getCertKeyFilename() {
  return cert_key_fn;
}

void Acme::setCertificateFilename(const char *fn) {
  cert_fn = fn;
  ReadCertificate();
}

const char *Acme::getCertificateFilename() {
  return cert_fn;
}

void Acme::setFilenamePrefix(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  filename_prefix = fn;
}

const char *Acme::getFilenamePrefix() {
  return filename_prefix;
}

void Acme::setFsPrefix(const char *fn) {
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  fs_prefix = fn;
}

void Acme::ReadAccountKey() {
  if (account_key_fn && (accountkey = ReadPrivateKey(account_key_fn))) {
    rsa = mbedtls_pk_rsa(*accountkey);
  }
}

void Acme::ReadCertKey() {
  if (cert_key_fn)
    certkey = ReadPrivateKey(cert_key_fn);
}

void Acme::setFtpServer(const char *s) {
  ftp_server = s;
}

void Acme::setFtpUser(const char *s) {
  ftp_user = s;
}

void Acme::setFtpPassword(const char *s) {
  ftp_pass = s;
}

void Acme::setFtpPath(const char *s) {
  ftp_path = s;
}

void Acme::setWebServer(httpd_handle_t ws) {
  webserver = ws;
}

/*
 * This is - intentionally - a simplistic HTTP GET handler.
 * It just knows how to return the data that the ACME protocol requires.
 *
 * Other HTTP requests should be serviced by possibly more intelligent handlers
 * in the application.
 */
esp_err_t Acme::acme_http_get_handler(httpd_req_t *req) {
  if (strcmp(req->uri, _acme->ValidationFile) == 0) {
    ESP_LOGD(acme_tag, "%s: URI %s", __FUNCTION__, req->uri);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, _acme->ValidationString, strlen(_acme->ValidationString));
  } else {
    ESP_LOGE(acme_tag, "%s: URI %s -> 404", __FUNCTION__, req->uri);
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, acme_http_404);
  }

  return ESP_OK;
}

void Acme::EnableLocalWebServer() {
  ESP_LOGI(acme_tag, "%s(%s)", __FUNCTION__, ValidationFile);
  httpd_uri_t	wsconf;
  esp_err_t	err;

  if (webserver == 0) {
    ESP_LOGE(acme_tag, "%s: internal error, webserver = 0", __FUNCTION__);
    return;
  }

  if (ws_registered && (ovf != NULL)) {
    // old ValidationFile
    httpd_unregister_uri_handler(webserver, ovf, HTTP_GET);
    free(ovf);
    ovf = NULL;
  }

  memset((void *)&wsconf, 0, sizeof(wsconf));
  wsconf.uri = strdup(ValidationFile);
  wsconf.method = HTTP_GET;
  wsconf.handler = acme_http_get_handler;

  if ((err = httpd_register_uri_handler(webserver, &wsconf)) != ESP_OK) {
    ESP_LOGE(acme_tag, "%s : failed to register URI handler for %s (%d %s)",
      __FUNCTION__, wsconf.uri, err, esp_err_to_name(err));
  } else {
    ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, wsconf.uri);
    ws_registered = true;
    ovf = (char *)wsconf.uri;
  }
}

void Acme::DisableLocalWebServer() {
  if (webserver == 0 || ovf == 0 || !ws_registered) {
    ESP_LOGE(acme_tag, "%s: failed 0", __FUNCTION__);
    return;
  }

  // Note this only works if ValidateFile isn't changed between invocations...
  httpd_unregister_uri_handler(webserver, ovf, HTTP_GET);
  free(ovf);
  ovf = NULL;
  ws_registered = false;

  ESP_LOGI(acme_tag, "%s: disabled local web server", __FUNCTION__);
}

/*
 * No memory management at all, just store a pointer.
 */
void Acme::setRootCertificateFilename(const char *root_fn) {
  root_certificate_fn = root_fn;
}

void Acme::setRootCertificate(const char *root_cert) {
  root_certificate = root_cert;
}

/*
 * This is a modified copy of Acme::ReadAccountInfo().
 * NREAD_INC is reused from that method.
 */
bool Acme::ReadRootCertificate() {
  if (root_certificate_fn == 0 || filename_prefix == 0) {
    ESP_LOGE(acme_tag, "%s: ACME files not configured", __FUNCTION__);
    return false;
  }
  char *fn = (char *)malloc(strlen(root_certificate_fn) + 5 + strlen(filename_prefix));
  sprintf(fn, "%s/%s", filename_prefix, root_certificate_fn);

  FILE *f = fopen(fn, "r");
  if (f == NULL) {
    ESP_LOGE(acme_tag, "Could not read root certificate from %s, %s", fn, strerror(errno));
    free(fn);
    return false;
  }

  // ESP-IDF VFS over SPIFFS doesn't allow use of fseek to determine file length, so read in chunks in that case
  // Potential over-allocation is limited to NREAD_INC bytes
  long len = fseek(f, 0L, SEEK_END);
  if (len == 0) {
    len = NREAD_INC;
  }
  ESP_LOGD(acme_tag, "Reading root certificate from %s", fn);
  free(fn);

  fseek(f, 0L, SEEK_SET);
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
    ESP_LOGD(acme_tag, "Reading -> %d bytes, total %d ", inc, total);
  }
  fclose(f);
  ESP_LOGD(acme_tag, "%s: %s", __FUNCTION__, buffer);

  if (root_certificate)
    free((void *)root_certificate);
  root_certificate = buffer;

  return true;
}

const char *Acme::AcmeClientVersion() {
  return _ACMECLIENT_VERSION;
}

/*
 * Utility function to read a file
 */

/*
 * This will read certificates from file, e.g. the ones obtained via ACME.
 * Note that we dynamically allocate memory per NREAD_INC, this is to work around
 * a filesystem deficiency : it won't report file size with seek().
 *
 * Caller must free allocated memory
 *
 * The path is used as is (no prefix added), and length read is returned in the 2nd param.
 */
#define	NREAD_INC	250
const unsigned char *Acme::ReadFile(const char *fn, int *plen) {
  FILE *f = fopen(fn, "r");
  if (f == 0) {
    ESP_LOGE(acme_tag, "Could not open file %s", fn);
    if (plen != 0) *plen = 0;
    return 0;
  }
  ESP_LOGD(acme_tag, "%s(%s)", __FUNCTION__, fn);
  long len = fseek(f, 0L, SEEK_END);
  (void)fseek(f, 0L, SEEK_SET);
  if (len == 0)
    len = NREAD_INC;
  char *buffer = (char *)malloc(len+1);
  size_t total = fread((void *)buffer, 1, len, f);
  buffer[total] = 0;
  int inc = total;
  while (inc == NREAD_INC) {
    len += NREAD_INC;
    buffer = (char *)realloc((void *)buffer, len + 1);
    inc = fread((void *)(buffer + total), 1, NREAD_INC, f);
    total += inc;
    buffer[total] = 0;
  }
  fclose(f);
  ESP_LOGI(acme_tag, "%s: read from %s, len %d", __FUNCTION__, fn, total);

  buffer[total] = 0;
  if (plen != 0) *plen = total;
  return (const unsigned char *)buffer;
}

const char *Acme::returnstatus2string(return_status s) {
  switch (s) {
  case status_fail:	return "fail";
  case status_ok:	return "ok";
  case status_pending:	return "pending";
  default:		return "?";
  }
}
