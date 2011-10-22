/*
  This file is part of the PhantomJS project from Ofi Labs.

  Copyright (C) 2011 Ariya Hidayat <ariya.hidayat@gmail.com>
  Copyright (C) 2011 Ivan De Marino <ivan.de.marino@gmail.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <QAuthenticator>
#include <QDateTime>
#include <QDesktopServices>
#include <QNetworkDiskCache>
#include <QRegExp>

#include <iostream>
#include <QNetworkReply>
#include <QNetworkRequest>


#include "config.h"
#include "cookiejar.h"
#include "networkaccessmanager.h"

static const char *toString(QNetworkAccessManager::Operation op)
{
    const char *str = 0;
    switch (op) {
    case QNetworkAccessManager::HeadOperation:
        str = "HEAD";
        break;
    case QNetworkAccessManager::GetOperation:
        str = "GET";
        break;
    case QNetworkAccessManager::PutOperation:
        str = "PUT";
        break;
    case QNetworkAccessManager::PostOperation:
        str = "POST";
        break;
    case QNetworkAccessManager::DeleteOperation:
        str = "DELETE";
        break;
    default:
        str = "?";
        break;
    }
    return str;
}

// public:
NetworkAccessManager::NetworkAccessManager(QObject *parent, const Config *config)
    : QNetworkAccessManager(parent)
    , m_ignoreSslErrors(config->ignoreSslErrors())
    , m_idCounter(0)
    , m_networkDiskCache(0)
{
    if (!config->cookiesFile().isEmpty()) {
        setCookieJar(new CookieJar(config->cookiesFile()));
    }

    if (config->diskCacheEnabled()) {
        m_networkDiskCache = new QNetworkDiskCache(this);
        m_networkDiskCache->setCacheDirectory(QDesktopServices::storageLocation(QDesktopServices::CacheLocation));
        if (config->maxDiskCacheSize() >= 0)
            m_networkDiskCache->setMaximumCacheSize(config->maxDiskCacheSize() * 1024);
        setCache(m_networkDiskCache);
    }

    connect(this, SIGNAL(authenticationRequired(QNetworkReply*,QAuthenticator*)), SLOT(provideAuthentication(QNetworkReply*,QAuthenticator*)));
    connect(this, SIGNAL(finished(QNetworkReply*)), SLOT(handleFinished(QNetworkReply*)));
}

void NetworkAccessManager::setUserName(const QString &userName)
{
    m_userName = userName;
}

void NetworkAccessManager::setPassword(const QString &password)
{
    m_password = password;
}

QVariantList NetworkAccessManager::blockedUrls() const
{
    return m_blockedUrls;
}

void NetworkAccessManager::setBlockedUrls(const QVariantList &urls)
{
    m_blockedUrls = urls;
}


/* Accept all navigation requests except as specifically blocked in the blockedUrls list.
 * Blocked URLs can be either regular expressions or strings -- in which case the strings
 * are prefix-matched against the loaded URL.  E.g., "http://target.com" will block *all*
 * URLs starting with "http://target.com" but not http://www.target.com or https://target.com
 */
// protected
bool NetworkAccessManager::shouldLoadUrl ( const QString & url )
{
    return true;
    if(m_blockedUrls.isEmpty()) return true;

    QVariantList::Iterator it = m_blockedUrls.begin();
    while(it != m_blockedUrls.end()) {
        QVariant item = *it;

        if(item.canConvert<QRegExp>()) {
            QRegExp regexValue = item.toRegExp();
            if(regexValue.indexIn(url) != -1) {
                std::cerr << "Blocking URL " << qPrintable(url) << " due to regex match." << std::endl;
                return false;
            }
        } else if(item.canConvert<QString>()) {
            QString stringValue = item.toString();
            if(url.indexOf(stringValue) == 0) {
                std::cerr << "Blocking URL " << qPrintable(url) << " due to string match. << std::endl";
                return false;
            }
        }
        ++it;
    }
    return true;
}


// protected:
QNetworkReply *NetworkAccessManager::createRequest(Operation op, const QNetworkRequest & req, QIODevice * outgoingData)
{
//    std::cerr << "Network request creating for " << qPrintable(req.url().toString()) << std::endl;
    QNetworkReply *reply;

    if(!shouldLoadUrl(req.url().toString())) {
        std::cerr << "Blocking network request to " << qPrintable(req.url().toString()) << std::endl;
        QNetworkRequest fakeRequest = QNetworkRequest(req);
        fakeRequest.setUrl(QUrl("about:blank"));
        reply = QNetworkAccessManager::createRequest(op, fakeRequest, outgoingData);
    } else {
    // Pass duty to the superclass - Nothing special to do here (yet?)
        reply = QNetworkAccessManager::createRequest(op, req, outgoingData);
    }

    if(m_ignoreSslErrors) {
        reply->ignoreSslErrors();
    }

    QVariantList headers;
    foreach (QByteArray headerName, req.rawHeaderList()) {
        QVariantMap header;
        header["name"] = QString::fromUtf8(headerName);
        header["value"] = QString::fromUtf8(req.rawHeader(headerName));
        headers += header;
    }

    m_idCounter++;
    m_ids[reply] = m_idCounter;

    QVariantMap data;
    data["id"] = m_idCounter;
    data["url"] = req.url().toString();
    data["method"] = toString(op);
    data["headers"] = headers;
    data["time"] = QDateTime::currentDateTime();

    connect(reply, SIGNAL(readyRead()), this, SLOT(handleStarted()));
    connect(reply, SIGNAL(sslErrors(const QList<QSslError> &)), this, SLOT(sslErrors(const QList<QSslError> &)));

    emit resourceRequested(data);
    return reply;
}

void NetworkAccessManager::handleStarted()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply*>(sender());
    if (!reply)
        return;
    if (m_started.contains(reply))
        return;

    m_started += reply;

    QVariantList headers;
    foreach (QByteArray headerName, reply->rawHeaderList()) {
        QVariantMap header;
        header["name"] = QString::fromUtf8(headerName);
        header["value"] = QString::fromUtf8(reply->rawHeader(headerName));
        headers += header;
    }

    QVariantMap data;

    data["id"] = m_ids.value(reply);
    data["url"] = reply->url().toString();
    data["status"] = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    data["statusText"] = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
    data["contentType"] = reply->header(QNetworkRequest::ContentTypeHeader);
    data["bodySize"] = reply->size();
    data["redirectURL"] = reply->header(QNetworkRequest::LocationHeader);
    data["headers"] = headers;
    data["time"] = QDateTime::currentDateTime();

    emit resourceReceived(data);
}

void NetworkAccessManager::handleFinished(QNetworkReply *reply)
{
    QVariantList headers;
    foreach (QByteArray headerName, reply->rawHeaderList()) {
        QVariantMap header;
        header["name"] = QString::fromUtf8(headerName);
        header["value"] = QString::fromUtf8(reply->rawHeader(headerName));
        headers += header;
    }

    QVariantMap data;
    data["stage"] = "end";
    data["id"] = m_ids.value(reply);
    data["url"] = reply->url().toString();
    data["status"] = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    data["statusText"] = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
    data["contentType"] = reply->header(QNetworkRequest::ContentTypeHeader);
    data["redirectURL"] = reply->header(QNetworkRequest::LocationHeader);
    data["headers"] = headers;
    data["time"] = QDateTime::currentDateTime();

    m_ids.remove(reply);
    m_started.remove(reply);

    if(reply->error() == QNetworkReply::NoError && !reply->header(QNetworkRequest::ContentTypeHeader).isValid()) {
        std::cerr << "WARNING: Missing content-type header from reply: ["<< qPrintable(data["status"].toString()) <<
         "] [" << qPrintable(data["statusText"].toString()) << "] from " << qPrintable(data["url"].toString()) <<
         std::endl;
    }

    emit resourceReceived(data);
}

void NetworkAccessManager::sslErrors(const QList<QSslError> & errors) {
  if (!m_ignoreSslErrors) {
    foreach (QSslError error, errors) {
      std::cerr << "SSL Error: " << qPrintable(error.errorString()) << std::endl;
    }
  }
}

void NetworkAccessManager::provideAuthentication(QNetworkReply *reply, QAuthenticator *authenticator)
{
    Q_UNUSED(reply);
    authenticator->setUser(m_userName);
    authenticator->setPassword(m_password);
}
