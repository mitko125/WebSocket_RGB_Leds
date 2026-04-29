/*
 * This module implements the ACME (Automated Certicifate Management Environment) protocol.
 * A client for Let's Encrypt (https://letsencrypt.org).
 *
 * Copyright (c) 2019, 2020, 2021, 2023, 2024 Danny Backx
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


#ifndef	_ACME_H_
#define	_ACME_H_

// Note : ArduinoJson v6 required.
#include <ArduinoJson.h>

#include <sys/socket.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_http_client.h>
#if USE_EXTERNAL_WEBSERVER
#include <FtpClient.h>
#endif
#include <esp_http_server.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include <mbedtls/x509_csr.h>

    enum return_status {
      status_fail,
      status_pending,
      status_ok
    };
class Acme {
  public:
			Acme();
			~Acme();

    const char		*AcmeClientVersion();

    void		NetworkConnected(void *ctx, wifi_event_sta_connected_t *event);
    void		NetworkDisconnected(void *ctx, wifi_event_sta_disconnected_t *event);

    // Getters / setters
    void			setUrl(const char *);
    void			setAltUrl(const int ix, const char *fn);
    void			setEmail(const char *);
    void			setAcmeServer(const char *);
    void			setAccountFilename(const char *);
    void			setAccountKeyFilename(const char *);
    void			setOrderFilename(const char *);
    void			setCertKeyFilename(const char *);
    const char			*getCertKeyFilename();
    void			setFilenamePrefix(const char *);
    const char			*getFilenamePrefix();
    void			setFsPrefix(const char *);
    void			setCertificateFilename(const char *);
    const char			*getCertificateFilename();
    void			setFtpServer(const char *);
    void			setFtpUser(const char *);
    void			setFtpPassword(const char *);
    void			setFtpPath(const char *);
    void			setWebServer(httpd_handle_t);
    void			setRootCertificateFilename(const char *);
    void			setRootCertificate(const char *);
    void			ignoreConnected(bool);

    bool			loop(time_t now);	// Return true on a certificate change
    bool			HaveValidCertificate(time_t);
    bool			HaveValidCertificate();

    // Private keys
    void			GenerateAccountKey();
    void			GenerateCertificateKey();
    mbedtls_pk_context		*getAccountKey();
    mbedtls_pk_context		*getCertificateKey();
    void			setAccountKey(mbedtls_pk_context *ak);
    void			setCertificateKey(mbedtls_pk_context *ck);

    bool			CreateNewAccount();
    /*
     * Run the ACME client FSM (finite state machine)
     * Returns true on a certificate change.
     */
    bool			AcmeProcess(time_t);
    mbedtls_x509_crt		*getCertificate();

    void			CreateNewOrder();
    void			OrderRemove();
    void			CertificateDownload();
    void			RenewCertificate();
    void			GetOrderStatus();

    
    void			WaitForTimesync(bool);
    void			TimeSync(struct timeval *);

    bool			checkConfig();

    // Utilify function to read a file, caller must free buffer
    const unsigned char		*ReadFile(const char *fn, int *plen);

  private:
    constexpr const static char	*acme_tag = "Acme";	// For ESP_LOGx calls

    // This replaces a bool return value for some functions that can't always 
    // have a good outcome immediately due to asynchronous behaviour.
    const char			*returnstatus2string(return_status s);

    const char			*account_key_fn;	// Account private key filename
    const char			*cert_key_fn;		// Certificate private key filename
    const char			*email_address;		// Email address in the account
    const char			*acme_url;	// URL for which we're getting a certificate
    const char			**alt_urls;	// URL for which we're getting a certificate
    int				alt_url_cnt;
    const char			*acme_server_url;	// ACME server
    const char			*fs_prefix;		// Root of the filesystem
    const char			*filename_prefix;	// e.g. /spiffs
    const char			*account_fn;	// Account status json filename, e.g. "account.json"
    const char			*order_fn;	// Order status json filename, e.g. "order.json"
    const char			*cert_fn;	// Certificate filename, e.g. "certificate.pem"

    const char			*ftp_server;
    const char			*ftp_user;
    const char			*ftp_pass;
    const char			*ftp_path;

    // String constants for use in the code
    const char			*acme_agent_header =		"User-Agent";
    const char			*acme_content_type =		"Content-Type";
    const char			*acme_jose_json =		"application/jose+json";
    const char			*acme_accept_header =		"Accept";
    const char			*acme_accept_pem_chain =	"application/pem-certificate-chain";
    // const char *acme_accept_der = "application/pkix-cert";
    // const char *acme_accept_der = "application/pkcs7-mime";
    const char			*well_known =			"/.well-known/acme-challenge/";
    const char			*acme_http_01 =			"http-01";

    // JSON
    const char			*acme_json_status =		"status";
    const char			*acme_json_type =		"type";
    const char			*acme_json_detail =		"detail";
    const char			*acme_json_value =		"value";
    const char			*acme_json_url =		"url";
    const char			*acme_json_token =		"token";
    const char			*acme_json_location =		"location";
    const char			*acme_json_contact =		"contact";
    const char			*acme_json_key =		"key";
    const char			*acme_json_kty =		"kty";
    const char			*acme_json_n =			"n";
    const char			*acme_json_e =			"e";
    const char			*acme_json_expires =		"expires";
    const char			*acme_json_finalize =		"finalize";
    const char			*acme_json_certificate =	"certificate";
    const char			*acme_json_identifiers =	"identifiers";
    const char			*acme_json_authorizations =	"authorizations";
    const char			*acme_json_retry_after =	"retry-after";

    // Status
    const char			*acme_status_valid =		"valid";
    const char			*acme_status_ready =		"ready";
    const char			*acme_status_processing =	"processing";
    const char			*acme_status_pending =		"pending";
    const char			*acme_status_invalid =		"invalid";
    const char			*acme_status_downloaded =	"downloaded";

    // Identify ourselves as :
    const char *acme_agent_template = "Esp32 ACME client library/0.2, built on esp-idf %s (https://esp32-acme-client.sourceforge.io)";

    // Format strings for protocol queries :
    const char *acme_jwk_template = "{\"kty\": \"RSA\", \"n\": \"%s\", \"e\": \"%s\"}";
    const char *acme_mailto = "mailto:";
    const char *new_account_template =
      "{ \"termsOfServiceAgreed\": true, \"contact\": [ \"%s%s\" ], \"onlyReturnExisting\": %s}";
    const char *new_account_template_no_email =
      "{\n  \"termsOfServiceAgreed\": true,\n  \"resource\": [\n    \"new-reg\"\n  ]\n}";
    const char *new_order_template =
      "{\n  \"identifiers\": [\n    {\n      \"type\": \"dns\", \"value\": \"%s\"\n    }\n  ]\n}";
    const char *new_order_template2 =
      "{\n  \"identifiers\": [\n    %s  ]\n}";
    const char *new_order_subtemplate =
      "{ \"type\": \"dns\", \"value\": \"%s\" }\n";
    const char *csr_template =
      "{\n\t\"resource\" : \"new-authz\",\n\t\"identifier\" :\n\t{\n\t\t\"type\" : \"dns\",\n\t\t\"value\" : \"%s\"\n\t}\n}";
    const char *csr_format = "{ \"csr\" : \"%s\" }";
    const char *acme_message_jwk_template1 =
      "{\"url\": \"%s\", \"jwk\": %s, \"alg\": \"RS256\", \"nonce\": \"%s\"}";
    const char *acme_message_jwk_template2 =
      "{\n  \"protected\": \"%s\",\n  \"payload\": \"%s\",\n  \"signature\": \"%s\"\n}";
    const char *acme_message_kid_template =
      "{\n  \"protected\": \"%s\",\n  \"payload\": \"%s\",\n  \"signature\": \"%s\"\n}";

    // These are needed in static member functions
    // We scan HTTP headers in replies for these :
    constexpr static const char *acme_nonce_header = "Replay-Nonce";
    constexpr static const char *acme_location_header = "Location";
    constexpr static const char *acme_retry_after_header = "Retry-After";

    constexpr static const char *acme_http_404 = "404 File not found";

    // These are the static member functions
    static esp_err_t NonceHttpEvent(esp_http_client_event_t *event);
    static esp_err_t HttpEvent(esp_http_client_event_t *event);
    static esp_err_t acme_http_get_handler(httpd_req_t *);

    // These store the info obtained in one of the static member functions
    void setNonce(char *);
    char *GetNonce();
    void setLocation(const char *);
    void clearQueryHeaders(void);
    void setRetryAfter(const char *);

    // Figure out what to do with the Location field in HTTP headers
    enum query_type {
      query_unknown,
      query_account,
      query_order,
      query_finalize,
    };

    query_type	qt;
    void	setQueryType(enum query_type);
    void	resetQueryType();
    const char	*QueryTypeToString(query_type);

    // Helper functions
    time_t	timestamp(const char *);
    time_t	TimeMbedToTimestamp(mbedtls_x509_time t);

    //
    void	StoreFileOnWebserver(char *localfn, char *remotefn);
    void	RemoveFileFromWebserver(char *remotefn);

    // Crypto stuff to build the ACME messages (see protocols such as JWS, JOSE, JWK, ..)
    char	*Base64(const char *);
    char	*Base64(const char *, int);
    char	*Unbase64(const char *s);
    char	*Signature(const char *, const char *);
    char	*MakeMessageJWK(char *url, char *payload, char *jwk);
    char	*MakeJWK();
    char	*MakeMessageKID(const char *url, const char *payload);
    char	*MakeProtectedKID(const char *query);
    char	*JWSThumbprint();

    // Do an ACME query
    char	*PerformWebQuery(const char *, const char *, const char *, const char *accept_msg);

    void	QueryAcmeDirectory();
    bool	RequestNewNonce();
    void	ClearDirectory();

    mbedtls_pk_context	*GeneratePrivateKey();
    bool	ReadPrivateKey();
    mbedtls_pk_context	*ReadPrivateKey(const char *fn);
    void	WritePrivateKey();
    void	WritePrivateKey(const char *);
    void	WritePrivateKey(mbedtls_pk_context *pk, const char *fn);
    void	ReadAccountKey();
    void	ReadCertKey();
    bool	ReadRootCertificate();

    bool	RequestNewAccount(const char *contact, bool onlyExisting);
    bool	ReadAccountInfo();
    void	WriteAccountInfo();
    void	ClearAccount();

    void	RequestNewOrder(const char *url);
    void	RequestNewOrder(const char *url, const char **alt_urls);
    void	ClearOrder();
    void	ClearOrderContent();
    bool	ReadOrderInfo();
    void	WriteOrderInfo();
    return_status	ValidateOrder();
    return_status	ValidateAlertServer();
    void	EnableLocalWebServer();
    void	DisableLocalWebServer();

    int		DownloadAuthorizationResource();
    bool	CreateValidationFile(const char *localfn, const char *token);
    char	*CreateValidationString(const char *token);
    void	ClearChallenge();

    void	FinalizeOrder();
    bool	DownloadCertificate();

    // All stubs of ArduinoJson dependent functions.
#if ARDUINOJSON_VERSION_MAJOR < 7
    void 	ReadAccount(DynamicJsonDocument &);
    void	ReadChallenge(DynamicJsonDocument &);
    return_status	ReadAuthorizationReply(DynamicJsonDocument &);
    void	ReadOrder(DynamicJsonDocument &);
    void	AugmentOrder(DynamicJsonDocument &);
    void	ReadFinalizeReply(DynamicJsonDocument &);
#else
    void 	ReadAccount(JsonDocument &);
    void	ReadChallenge(JsonDocument &);
    return_status	ReadAuthorizationReply(JsonDocument &);
    void	ReadOrder(JsonDocument &);
    void	AugmentOrder(JsonDocument &);
    void	ReadFinalizeReply(JsonDocument &);
#endif

    char	*GenerateCSR();
    int		CreateAltUrlList(mbedtls_x509write_csr req);

    void	SetAcmeUserAgentHeader(esp_http_client_handle_t);

    void	ReadCertificate();		// From local file
    void	CreateDirectories(const char *path);

    // Forward declarations
    struct Directory;
    struct Account;
    struct Order;
    struct Challenge;

    /*
     * private class fields
     */
    Directory	*directory;
    Account	*account;
    Order	*order;
    Challenge	*challenge;

    char	*nonce;
    int		nonce_use;
    char	*account_location;
    char	*reply_buffer;
    int		reply_buffer_len;
    char	*retry_after;

    int		http01_ix;
    time_t	last_run;
    bool	connected, ignore_connected;

    mbedtls_rsa_context		*rsa;
    mbedtls_ctr_drbg_context	*ctr_drbg;
    mbedtls_entropy_context	*entropy;
    mbedtls_pk_context		*accountkey;	// Account private key
    mbedtls_pk_context		*certkey;	// Certificate private key

    mbedtls_x509_crt		*certificate;
    const char			*root_certificate_fn;	// File name of the root cert (PEM)
    const char			*root_certificate;

    // FTP server, if we have one
    httpd_handle_t	webserver;
    char		*ValidationString;	// The string to reply to the ACME server
    char		*ValidationFile;	// File name that must be queried
    httpd_uri_t		*wsconf;
    bool		ws_registered;
    char		*ovf;

    /*
     * ACME Protocol data definitions
     * Note : these aren't exactly what the RFC says, they're what we need.
     */
    struct Directory {
      char	*newAccount,
		*newNonce,
		*newOrder;
    };

    struct Account {			// See ACME RFC § 7.1.2
      char	*status;
      char	**contact;
      bool	termsOfServiceAgreed;
      char	*orders;
      char	*key_type, *key_id, *key_e;
      char	*initialIp,
		*createdAt;
      time_t	t_createdAt;
      char	*location;		// Used to be a class field
    };

    struct Identifier {			// See ACME RFC § 7.1.3
      char		*_type;
      char		*value;
    };
    struct Order {
      char		*status;
      char		*expires;	// timestamp
      time_t		t_expires;
      Identifier	*identifiers;
      char		**authorizations;
      char		*finalize;	// URL for us to call
      char		*certificate;	// URL to download the certificate
      char		*retry_after;
      char		*location;	// URL to query Order
    };

    struct ChallengeItem {
      char		*_type;
      char		*status;
      char		*url;
      char		*token;
      bool		active;		// internal
    };

    struct Challenge {
      Identifier	*identifiers;
      char		*status;
      char		*expires;
      time_t		t_expires;
      ChallengeItem	*challenges;
    };

    /*
     * Time Sync
     */
    bool wait_for_timesync;
    bool time_synced;
};

extern Acme *_acme;
#endif	/* _ACME_H_ */
