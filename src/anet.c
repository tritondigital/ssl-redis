/* anet.c -- Basic TCP socket stuff made a bit less boring
 *
 * Copyright (c) 2006-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "fmacros.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "anet.h"

#define PASSWORD "zum27lar"

int password_callback(char* buffer, int num, int rwflag, void* userdata) {
    if (num < (strlen(PASSWORD) + 1)) {
  return(0);
    }
    strcpy(buffer, PASSWORD);
    return strlen(PASSWORD);
}

int verify_callback(int ok, X509_STORE_CTX* store) {
  char data[255];

  if (!ok) {
    X509* cert = X509_STORE_CTX_get_current_cert(store);
    int depth = X509_STORE_CTX_get_error_depth(store);
    int err = X509_STORE_CTX_get_error(store);

    printf("Error with certificate at depth: %d!\n", depth);
    X509_NAME_oneline(X509_get_issuer_name(cert), data, 255);
    printf("\tIssuer: %s\n", data);
    X509_NAME_oneline(X509_get_subject_name(cert), data, 255);
    printf("\tSubject: %s\n", data);
    printf("\tError %d: %s\n", err, X509_verify_cert_error_string(err));
  }

  return ok;
} 

static void anetSetError(char *err, const char *fmt, ...)
{
    va_list ap;

    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, ANET_ERR_LEN, fmt, ap);
    va_end(ap);
}

int anetNonBlock(char *err, int fd)
{
    int flags;

    /* Set the socket nonblocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */

    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        anetSetError(err, "fcntl(F_GETFL): %s", strerror(errno));
        return ANET_ERR;
    }
    
// TODO: BBROERMAN _ Removed non-blocking    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        anetSetError(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetTcpNoDelay(char *err, int fd)
{
    int yes = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1)
    {
        anetSetError(err, "setsockopt TCP_NODELAY: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetSetSendBuffer(char *err, int fd, int buffsize)
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) == -1)
    {
        anetSetError(err, "setsockopt SO_SNDBUF: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetTcpKeepAlive(char *err, int fd)
{
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        anetSetError(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetResolve(char *err, char *host, char *ipbuf)
{
    struct sockaddr_in sa;

    sa.sin_family = AF_INET;
    if (inet_aton(host, &sa.sin_addr) == 0) {
        struct hostent *he;

        he = gethostbyname(host);
        if (he == NULL) {
            anetSetError(err, "can't resolve: %s", host);
            return ANET_ERR;
        }
        memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
    }
    strcpy(ipbuf,inet_ntoa(sa.sin_addr));
    return ANET_OK;
}

static int anetCreateSocket(char *err, int domain) {
    int s, on = 1;
    if ((s = socket(domain, SOCK_STREAM, 0)) == -1) {
        anetSetError(err, "creating socket: %s", strerror(errno));
        return ANET_ERR;
    }

    /* Make sure connection-intensive things like the redis benckmark
     * will be able to close/open sockets a zillion of times */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
        anetSetError(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return ANET_ERR;
    }
    return s;
}

#define ANET_CONNECT_NONE 0
#define ANET_CONNECT_NONBLOCK 1
static int anetTcpGenericConnect(char *err, char *addr, int port, int flags)
{
    int s;
    struct sockaddr_in sa;

    if ((s = anetCreateSocket(err,AF_INET)) == ANET_ERR)
        return ANET_ERR;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_aton(addr, &sa.sin_addr) == 0) {
        struct hostent *he;

        he = gethostbyname(addr);
        if (he == NULL) {
            anetSetError(err, "can't resolve: %s", addr);
            close(s);
            return ANET_ERR;
        }
        memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
    }
    if (flags & ANET_CONNECT_NONBLOCK) {
        if (anetNonBlock(err,s) != ANET_OK)
            return ANET_ERR;
    }
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        if (errno == EINPROGRESS &&
            flags & ANET_CONNECT_NONBLOCK)
            return s;

        anetSetError(err, "connect: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return s;
}

int anetTcpConnect(char *err, char *addr, int port)
{
    return anetTcpGenericConnect(err,addr,port,ANET_CONNECT_NONE);
}

int anetTcpNonBlockConnect(char *err, char *addr, int port)
{
    return anetTcpGenericConnect(err,addr,port,ANET_CONNECT_NONBLOCK);
}

int anetUnixGenericConnect(char *err, char *path, int flags)
{
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == ANET_ERR)
        return ANET_ERR;

    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (flags & ANET_CONNECT_NONBLOCK) {
       if (anetNonBlock(err,s) != ANET_OK)
         return ANET_ERR;
  }
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) == -1) {
        if (errno == EINPROGRESS &&
            flags & ANET_CONNECT_NONBLOCK)
            return s;

        anetSetError(err, "connect: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return s;
}

int anetUnixConnect(char *err, char *path)
{
    return anetUnixGenericConnect(err,path,ANET_CONNECT_NONE);
}

int anetUnixNonBlockConnect(char *err, char *path)
{
    return anetUnixGenericConnect(err,path,ANET_CONNECT_NONBLOCK);
}

/* Like read(2) but make sure 'count' is read before to return
 * (unless error or EOF condition is encountered) */
int anetRead(int fd, char *buf, int count)
{
    int nread, totlen = 0;
    while(totlen != count) {
        nread = read(fd,buf,count-totlen);
        if (nread == 0) return totlen;
        if (nread == -1) return -1;
        totlen += nread;
        buf += nread;
    }
    return totlen;
}

/* Like write(2) but make sure 'count' is read before to return
 * (unless error is encountered) */
int anetWrite(int fd, char *buf, int count)
{
    int nwritten, totlen = 0;
    while(totlen != count) {
        nwritten = write(fd,buf,count-totlen);
        if (nwritten == 0) return totlen;
        if (nwritten == -1) return -1;
        totlen += nwritten;
        buf += nwritten;
    }
    return totlen;
}

static int anetListen(char *err, int s, struct sockaddr *sa, socklen_t len) {
    if (bind(s,sa,len) == -1) {
        anetSetError(err, "bind: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    if (listen(s, 511) == -1) { /* the magic 511 constant is from nginx */
        anetSetError(err, "listen: %s", strerror(errno));
        close(s);
        return ANET_ERR;
    }
    return ANET_OK;
}

int anetTcpServer(char *err, int port, char *bindaddr)
{
    int s;
    struct sockaddr_in sa;

    if ((s = anetCreateSocket(err,AF_INET)) == ANET_ERR)
        return ANET_ERR;

    memset(&sa,0,sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bindaddr && inet_aton(bindaddr, &sa.sin_addr) == 0) {
        anetSetError(err, "invalid bind address");
        close(s);
        return ANET_ERR;
    }
    if (anetListen(err,s,(struct sockaddr*)&sa,sizeof(sa)) == ANET_ERR)
        return ANET_ERR;
    return s;
}

int anetUnixServer(char *err, char *path, mode_t perm)
{
    int s;
    struct sockaddr_un sa;

    if ((s = anetCreateSocket(err,AF_LOCAL)) == ANET_ERR)
        return ANET_ERR;

    memset(&sa,0,sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (anetListen(err,s,(struct sockaddr*)&sa,sizeof(sa)) == ANET_ERR)
        return ANET_ERR;
    if (perm)
        chmod(sa.sun_path, perm);
    return s;
}

static int anetGenericAccept(char *err, int s, struct sockaddr *sa, socklen_t *len) {
    int fd;
    while(1) {
        fd = accept(s,sa,len);
        if (fd == -1) {
            if (errno == EINTR)
                continue;
            else {
                anetSetError(err, "accept: %s", strerror(errno));
                return ANET_ERR;
            }
        }
        break;
    }
    return fd;
}

int anetTcpAccept(char *err, int s, char *ip, int *port) {
    int fd;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == ANET_ERR)
        return ANET_ERR;

    if (ip) strcpy(ip,inet_ntoa(sa.sin_addr));
    if (port) *port = ntohs(sa.sin_port);
    return fd;
}

int anetUnixAccept(char *err, int s) {
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = anetGenericAccept(err,s,(struct sockaddr*)&sa,&salen)) == ANET_ERR)
        return ANET_ERR;

    return fd;
}

int anetPeerToString(int fd, char *ip, int *port) {
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);

    if (getpeername(fd,(struct sockaddr*)&sa,&salen) == -1) return -1;
    if (ip) strcpy(ip,inet_ntoa(sa.sin_addr));
    if (port) *port = ntohs(sa.sin_port);
    return 0;
}

int anetSSLAccept( char *err, int fd, struct redisServer server, anetSSLConnection *ctn) {

  ctn->sd = -1;
  ctn->ctx = NULL;
  ctn->ssl = NULL;
  ctn->bio = NULL;

  if( fd == -1 ) {
    return ANET_ERR;
  }
  ctn->sd = fd;

  // Create the SSL Context ( server method )
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
  ctn->ctx = ctx;

   /*
     You will need to generate certificates, the root certificate authority file, the private key file, and the random file yourself.
     Google will help. The openssl executable created when you compiled OpenSSL can do all this.
   */

    // Load trusted root authorities
    SSL_CTX_load_verify_locations(ctx, NULL, server.ssl_root_dir);

    // Sets the default certificate password callback function. Read more under the Certificate Verification section.
    SSL_CTX_set_default_passwd_cb(ctx, password_callback);

    // Sets the certificate file to be used.
    SSL_CTX_use_certificate_file(ctx, server.ssl_cert_file, SSL_FILETYPE_PEM);

    // Sets the private key file to be used.
    SSL_CTX_use_PrivateKey_file(ctx, server.ssl_pk_file, SSL_FILETYPE_PEM);

    // Set the maximum depth to be used verifying certificates
    // Due to a bug, this is not enforced. The verify callback must enforce it.
    SSL_CTX_set_verify_depth(ctx, 1);

    // Set the certificate verification callback.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER /* | SSL_VERIFY_FAIL_IF_NO_PEER_CERT */, verify_callback);

    /*
      End certificate verification setup.
    */

    // We need to load the Diffie-Hellman key exchange parameters.
    // First load dh1024.pem (you DID create it, didn't you?)
    BIO* bio = BIO_new_file(server.ssl_dhk_file, "r");

    // Did we get a handle to the file?
    if (bio == NULL) {
      anetSetError(err, "SSL Accept: Couldn't open DH param file");
      anetCleanupSSL( ctn);
      return ANET_ERR;
    }

    // Read in the DH params.
    DH* ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);

    // Free up the BIO object.
    BIO_free(bio);

    // Set up our SSL_CTX to use the DH parameters.
    if (SSL_CTX_set_tmp_dh(ctx, ret) < 0) {
      anetSetError(err, "SSL Accept: Couldn't set DH parameters");
      anetCleanupSSL( ctn );
      return ANET_ERR;
    }

    // Now we need to generate a RSA key for use.
    // 1024-bit key. If you want to use something stronger, go ahead but it must be a power of 2. Upper limit should be 4096.
    RSA* rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);

    // Set up our SSL_CTX to use the generated RSA key.
    if (!SSL_CTX_set_tmp_rsa(ctx, rsa)) {
      anetSetError(err, "SSL Accept: Couldn't set RSA Key");
      anetCleanupSSL( ctn );
      return ANET_ERR;
    }

    // Free up the RSA structure.
    RSA_free(rsa);

    /*
      For some reason many tutorials don't include this...

      Servers must specify the ciphers they can use, to verify that both the client and the server can use the same cipher.
      If you don't do this, you'll get errors relating to "no shared ciphers" or "no common ciphers".

      In this case, we allow ALL ciphers, even potentially insecure ones. For real-world use the string here should specify non-weak ciphers.

      An example: ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH
      All ciphers with the exception of: ones with anonymous Diffie-Hellman, low-strength ciphers, export ciphers, md5 hashing. Ordered from strongest to weakest.
      Note that as ciphers become broken, it will be necessary to change the available cipher list to remain secure.
    */

    SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    // Set up our SSL object as before
    SSL* ssl = SSL_new(ctx);
    ctn->ssl = ssl;
    
    // Set up our BIO object to use the client socket
    BIO* sslclient = BIO_new_socket(fd, BIO_NOCLOSE);
    ctn->bio = sslclient;

    // Set up our SSL object to use the BIO.
    SSL_set_bio(ssl, sslclient, sslclient);

    // Do SSL handshaking.
    int r = SSL_accept(ssl);

    // Something failed. Print out all the error information, since all of it may be relevant to the problem.
    if (r != 1) {
      char error[65535];

      ERR_error_string_n(ERR_get_error(), error, 65535);

      anetSetError(err, "SSL Accept: Error %d - %s ", SSL_get_error(ssl, r), error );

      // We failed to accept this client connection.
      // Ideally here you'll drop the connection and continue on.
      anetCleanupSSL( ctn );
      return ANET_ERR;
    }

    /* Verify certificate */
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
      anetSetError(err, "SSL Accept: Certificate failed verification!");
      // Ideally here you'll close this connection and continue on.
      anetCleanupSSL( ctn );
      return ANET_ERR;
    }

    return ANET_OK;
}

void anetSSLPrepare( ) {
  CRYPTO_malloc_init(); // Initialize malloc, free, etc for OpenSSL's use
  SSL_library_init(); // Initialize OpenSSL's SSL libraries
  SSL_load_error_strings(); // Load SSL error strings
  ERR_load_BIO_strings(); // Load BIO error strings
  OpenSSL_add_all_algorithms(); // Load all available encryption algorithms
}

void anetCleanupSSL( anetSSLConnection *ctn ) {
  if( NULL != ctn ) {
    if( NULL != ctn->bio ) {
      // Free up that BIO object we created.
      BIO_free_all(ctn->bio);
      ctn->bio = NULL;
    }
    if( NULL != ctn->ctx ) {
      // Remember, we also need to free up that SSL_CTX object!
      SSL_CTX_free(ctn->ctx);
      ctn->ctx = NULL;
    }
    if( NULL != ctn->ssl ) {
      // Remember, we also need to free up that SSL_CTX object!
      SSL_free(ctn->ssl);
      ctn->ssl = NULL;
    }
  }
}
