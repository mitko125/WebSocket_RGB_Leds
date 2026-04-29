ACME client library for ESP32

Copyright &copy; 2019, 2020, 2021, 2023, 2024 by Danny Backx

Introduction
============

ACME is a protocol (see <a href="https://tools.ietf.org/html/rfc8555">RFC8555</a>) for automatic certificate management.
Sites such as letsencrypt.org allow you to obtain free (no charge) certificates in an automated way
using the ACME protocol.

This library allows you to get certificates for IoT devices based on the ESP32.

Note that the source repo is now aimed at supporting this as a component that you can fetch via the idf.py component repository. So its structure may not be what you expect. Please use this repo only directly if you know about such structures; it's advised to grab acmeclient by using a command such as

  idf.py add-dependency dannybackx/acmeclient

which will end up fetching it into managed_components/danny.. .

HOW TO
======

Currently, I've chosen to implement this for devices behind a NAT firewall.
One of the ways in which you can allow an ACME server to validate that you're asking a certificate for
a website/device that you actually have control over, is the use of a web server.
There are two options here :
- you can do with one central web server on your site, if you allow the IoT devices to put temporary files there to validate theirselves against the ACME server. Any secured Linux box on which you provide access to its web server can easily be set up in this way.
- you can implement a web server in the IoT device directly (if you can spare the resources).

Current status and plans :
- (done) works as a part of my app against the staging server
- (done) polish up the API so it can be a library
- (done) run against the production server
- (done, on staging) renew certificate (I have three months to get there)
- (done, on staging) implement a local web server, authorize against that directly
- (done, on production) implement a local web server, authorize against that directly
- (done) an example showing how to use in a full (C++) application framework
- (done) an example showing how to use from a slightly modified esp-idf example, in C
- (busy) provide a C language interface (current status : works, but not integrated in source)

Note: due to a bug in some versions of the esp-idf framework, the code sometimes loses time (some seconds). A workaround for it is to set the esp_http_client buffer, this may not always work. If this bug doesn't occur, then we can create our private keys and obtain a valid certificate in under a minute, see the <a href="https://sourceforge.net/p/esp32-acme-client/code/HEAD/tree/trunk/typescript.production?format=raw">log</a> for that.

So, the time to fetch a certificate is under a minute (for a cert that stays valid for three months).

Details
=======

Build notes :
- you may have to augment default stack sizes such as
    CONFIG_SYSTEM_EVENT_TASK_STACK_SIZE=6144
    CONFIG_MAIN_TASK_STACK_SIZE=6144
  in the ESP-IDF "make menuconfig".

- as from esp-idf v4.3 you need to enable "Basic Auth" support for the esp-http-client.

- building the example requires you to copy an include file and change its contents to match your
  local requirements (e.g. your WiFi credentials) :
    % cp main/secrets.h.sample main/secrets.h
    % vi main/secrets.h
    % make

API :
- This is a C++ class, with several methods that you must call :
    Acme();				Constructor
    ~Acme();				Destructor

    void NetworkConnected(void *ctx, system_event_t *event);
    void NetworkDisconnected(void *ctx, system_event_t *event);
    					Call from network event handlers, see the example

    void loop(time_t now);
    					Similar to Arduino, call this regularly with the current timestamp.
					Certificates are valid for quite a while so calling this several time
					a second (see Arduino) is not necessary.

- Several of the other setters allow you to configure the library.
  Please note that these setters take a copy of the pointer. Ownership of the data is still with the caller.
  So the caller must not free the memory pointed to.
  The reason is to keep memory consumption low.

    void setUrl(const char *);				URL that we'll get a certificate for
    void setEmail(const char *);			Email address of the owner
    void setAcmeServer(const char *);			Which ACME server do we use
    void setAccountFilename(const char *);		File name on esp32 local storage for the account, e.g. account.json
    void setAccountKeyFilename(const char *);		File name on esp32 local storage for the account private key, e.g. account.pem
    void setOrderFilename(const char *);		File name on esp32 local storage for the order, e.g. order.json
    void setCertKeyFilename(const char *);		File name on esp32 local storage for the certificate private key, e.g. certkey.pem
    void setFilenamePrefix(const char *);		Prefix for filesystem on esp32, e.g. /fs
    void setCertificateFilename(const char *);		File name on esp32 local storage for the certificate, e.g. certificate.pem

    void setFtpServer(const char *);			For your local FTP server : hostname / ip address
    void setFtpUser(const char *);			Userid on your local FTP server
    void setFtpPassword(const char *);			Password of that user on your local FTP server
    void setFtpPath(const char *);			Path to the web server files on your local FTP server, e.d. /var/www/html

- Note that the path ".well-known/challenge" must already have been create on your FTP server, e.g.
    cd /var/www/html
    mkdir -p .well-known/challenge

- You can grab your certificate with
    mbedtls_x509_crt *getCertificate();

- See the example client, you will need to use one or more of the folowing calls to kickstart the process.
  Actuall processing is in the loop() function, or the underlying AcmeProcess().

    boolean CreateNewAccount();
    void CreateNewOrder();
    void RenewCertificate();

- Private key management from the Acme class :
    void GenerateAccountKey();
    void GenerateCertificateKey();
    mbedtls_pk_context *getAccountKey();
    mbedtls_pk_context *getCertificateKey();
    void setAccountKey(mbedtls_pk_context *ak);
    void setCertificateKey(mbedtls_pk_context *ck);

This class relies on modules provided with ESP-IDF :
- mbedtls
- vfs (filesystem access, and underlying filesystem)
- LittleFS (https://github.com/ARMmbed/littlefs.git and https://github.com/joltwallet/esp_littlefs.git) recommended
  as such a filesystem, not SPIFFS (popular but lacks functionality).

Note that a full sample implementation is in https://emptyesp32.sourceforge.io .

Versions since October 2021 are based on esp-idf v4.3 (previously v3.x).
Noteworthy changes for that :
- you'll need to supply a file with a root certificate. Any call to LetsEncrypt.org is over
  https and on v4.3 this requires such a certificate. Use these methods to provide it :
    void setRootCertificateFilename(const char *);
    void setRootCertificate(const char *);
- as a consequence, communication only works when the time is set, which adds to the
  complexity of your application as it basically all needs to triggered outside of
  initialisation code. In the sample application, this is handled in sntp_sync_notify() 
  but it can also be put in loop(), which is less readable.
