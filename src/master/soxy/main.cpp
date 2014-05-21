#include <QCoreApplication>
#include <QList>
#include <QSslCipher>
#include <QSslKey>
#include <QFile>
#include <QStringList>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cerrno>
#include <cassert>

#include "handler.h"
#include "conn.h"

Receiver::Receiver() {
	QFile certFile(QCoreApplication::arguments()[1]);
	certFile.open(QIODevice::ReadOnly);
	QSslCertificate cert(&certFile);
	assert(!cert.isNull());
	QFile keyFile(QCoreApplication::arguments()[2]);
	keyFile.open(QIODevice::ReadOnly);
	QSslKey key(&keyFile, QSsl::Rsa);
	assert(!key.isNull());
	config.setProtocol(QSsl::TlsV1);
	config.setCaCertificates(QList<QSslCertificate>() << cert);
	config.setLocalCertificate(cert);
	config.setPrivateKey(key);
}

void Receiver::handleConnection(int fd) {
	new Connection(fd, config);
}

Handler::Handler() {
	receiver = new Receiver;
	receiver->moveToThread(this);
	connect(this, SIGNAL(handleConnection(int)), receiver, SLOT(handleConnection(int)), Qt::QueuedConnection);
}

void Handler::run() {
	exec();
}

void Handler::putFd(int fd) {
	emit handleConnection(fd);
}

QList<Handler *> handlers;

Connection::Connection(int sock, QSslConfiguration &config) :
	inReady(false),
	outReady(false)
{
	connect(&timer, SIGNAL(timeout()), SLOT(deleteLater()));
	remote.setSocketDescriptor(sock);
	remote.setSslConfiguration(config);
	remote.setCiphers("HIGH:!LOW:!MEDIUM:!SSLv2:!aNULL:!eNULL:!DES:!3DES:!AES128:!CAMELLIA128");
	connect(&remote, SIGNAL(disconnected()), SLOT(deleteLater()));
	connect(&remote, SIGNAL(readyRead()), SLOT(incoming()));
	connect(&remote, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(error(QAbstractSocket::SocketError)));
	connect(&remote, SIGNAL(sslErrors(const QList<QSslError> &)), SLOT(error(const QList<QSslError> &)));
	connect(&remote, SIGNAL(encrypted()), SLOT(connectedRemote()));
	connect(&remote, SIGNAL(bytesWritten(qint64)), SLOT(tryWriteRemote()));
	remote.startServerEncryption();
	connect(&local, SIGNAL(disconnected()), SLOT(deleteLater()));
	connect(&local, SIGNAL(readyRead()), SLOT(outgoing()));
	connect(&local, SIGNAL(error(QLocalSocket::LocalSocketError)), SLOT(error(QLocalSocket::LocalSocketError)));
	connect(&local, SIGNAL(connected()), SLOT(connectedLocal()));
	connect(&local, SIGNAL(bytesWritten(qint64)), SLOT(tryWriteLocal()));
	local.connectToServer(QCoreApplication::arguments()[4]);
	touch();
}

void Connection::incoming() {
	QByteArray ar = remote.read(1024 * 1024);
	if (ar.isEmpty())
		return;
	inBuf += ar;
	tryWriteLocal();
	incoming(); // In case there's more data.
	touch();
}

void Connection::error(QAbstractSocket::SocketError) {
	fprintf(stderr, "Socket error: %s\n", remote.errorString().toLocal8Bit().data());
	deleteLater();
}

void Connection::error(QLocalSocket::LocalSocketError) {
	fprintf(stderr, "Local socket error: %s\n", local.errorString().toLocal8Bit().data());
	deleteLater();
}

void Connection::error(const QList<QSslError> &errors) {
	foreach(const QSslError &err, errors) {
		fprintf(stderr, "SSL error: %s\n", err.errorString().toLocal8Bit().data());
	}
	deleteLater();
}

void Connection::connectedRemote() {
	outReady = true;
	tryWriteRemote();
	touch();
}

void Connection::tryWriteRemote() {
	if (!outReady)
		return;
	qint64 amount = remote.write(outBuf);
	if (amount == -1)
		error(QAbstractSocket::UnknownSocketError);
	else
		outBuf.remove(0, amount);
	touch();
}

void Connection::outgoing() {
	QByteArray ar = local.read(1024 * 1024);
	if (ar.isEmpty())
		return;
	outBuf += ar;
	tryWriteRemote();
	outgoing(); // In case of more data
	touch();
}

void Connection::connectedLocal() {
	inReady = true;
	tryWriteLocal();
	touch();
}

void Connection::tryWriteLocal() {
	if (!inReady)
		return;
	qint64 amount = local.write(inBuf);
	if (amount == -1)
		error(QAbstractSocket::UnknownSocketError);
	else
		inBuf.remove(0, amount);
	touch();
}

void Connection::touch() {
	timer.start(1000 * 900); // 15 minutes of inactivity safety timer
}

void c(int err, const char *desc) {
	if (err < 0) {
		fprintf(stderr, "%s failed: %m\n", desc);
		exit(1);
	}
}

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	int tcount = QThread::idealThreadCount();
	if (tcount < 1)
		tcount = 1;
	for (int i = 0; i < tcount; i ++) {
		Handler *h = new Handler;
		h->start();
		handlers << h;
	}

	int sock = socket(AF_INET6, SOCK_STREAM, 0);
	c(sock, "socket");
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof addr);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(QCoreApplication::arguments()[3].toInt());
	c(bind(sock, static_cast<sockaddr *>(static_cast<void *>(&addr)), sizeof addr), "bind");
	c(listen(sock, 50), "listen");
	for (;;) {
		int accepted = accept(sock, NULL, NULL);
		if (accepted == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EMFILE || errno == ENFILE) {
				fprintf(stderr, "Too many opened sockets!\n");
				continue;
			}
			c(accepted, "accept");
		}
		int rand = random() % handlers.size();
		handlers[rand]->putFd(accepted);
	}
	return app.exec();
}
