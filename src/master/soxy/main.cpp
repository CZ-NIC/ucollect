/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <QCoreApplication>
#include <QList>
#include <QSslCipher>
#include <QSslKey>
#include <QFile>
#include <QStringList>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <cerrno>
#include <cassert>
#include <unistd.h>

#include "handler.h"
#include "conn.h"

bool Connection::enableCompression = false;

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
	if (Connection::enableCompression) {
		zStreamCompress.zalloc = Z_NULL;
		zStreamCompress.zfree = Z_NULL;
		zStreamCompress.opaque = Z_NULL;
		zStreamDecompress.zalloc = Z_NULL;
		zStreamDecompress.zfree = Z_NULL;
		zStreamDecompress.opaque = Z_NULL;
		if (deflateInit(&zStreamCompress, COMPRESSION_LEVEL) != Z_OK) {
			error("Could not initialize zlib (compression stream)");
			deleteLater();
			return;
		}
		if (inflateInit(&zStreamDecompress) != Z_OK) {
			error("Could not initialize zlib (decompression stream)");
			deleteLater();
			return;
		}
	}
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

Connection::~Connection() {
	if (Connection::enableCompression) {
		deflateEnd(&zStreamCompress);
		inflateEnd(&zStreamDecompress);
	}
}

void Connection::incoming() {
	QByteArray ar = remote.read(COMPRESSION_BUFFSIZE);
	if (ar.isEmpty())
		return;
	if (Connection::enableCompression) {
		unsigned int available_output;
		unsigned char *input_data = (unsigned char *)ar.data();
		zStreamDecompress.next_in = input_data;
		zStreamDecompress.avail_in = ar.size();

		while (zStreamDecompress.avail_in > 0) {
			zStreamDecompress.next_out = decompressOutBuffer;
			zStreamDecompress.avail_out = COMPRESSION_BUFFSIZE;
			int ret = inflate(&zStreamDecompress, Z_SYNC_FLUSH);
			if (ret == Z_DATA_ERROR) {
				deleteLater();
				return;
			}
			available_output = COMPRESSION_BUFFSIZE - zStreamDecompress.avail_out;
			if (available_output == 0)
				return;
			inBuf.append((char *)decompressOutBuffer, available_output);
		}
	} else {
		inBuf += ar;
	}
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

void Connection::error(const char * errstr) {
	fprintf(stderr, "%s\n", errstr);
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
	QByteArray ar = local.read(COMPRESSION_BUFFSIZE);
	if (ar.isEmpty())
		return;
	if (Connection::enableCompression) {
		unsigned int available_output;
		unsigned char *input_data = (unsigned char *)ar.data();
		zStreamCompress.next_in = input_data;
		zStreamCompress.avail_in = ar.size();

		while (zStreamCompress.avail_in > 0) {
			zStreamCompress.next_out = compressOutBuffer;
			zStreamCompress.avail_out = COMPRESSION_BUFFSIZE;
			//TODO: Comment Z_SYNC_FLUSH flag
			deflate(&zStreamCompress, Z_SYNC_FLUSH);
			available_output = COMPRESSION_BUFFSIZE - zStreamCompress.avail_out;
			if (available_output == 0)
				return;
			outBuf.append((char *)compressOutBuffer, available_output);
		}
	} else {
		outBuf += ar;
	}
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
		abort();
	}
}

QSet<pid_t> children;

int sock, tcount;

int sigs[] = {
	SIGHUP,
	SIGINT,
	SIGQUIT,
	SIGILL,
	SIGTRAP,
	SIGBUS,
	SIGFPE,
	SIGSEGV,
	SIGPIPE,
	SIGALRM,
	SIGTERM,
	SIGABRT, // Last, since we use abort for the sigaction too
	0
};

void doFork(QCoreApplication &app) {
	pid_t pid = fork();
	c(pid, "fork");
	if (pid) {
		children << pid;
		return;
	}
	// The child

	for (int *sig = sigs; *sig; sig ++) {
		struct sigaction action;
		memset(&action, 0, sizeof action);
		action.sa_handler = SIG_DFL;
		c(sigaction(*sig, &action, NULL), "action reset");
	}
	// TODO: Do we need the threads too, if we have prefork? Threads only didn't seem to work :-(.
	for (int i = 0; i < 2; i ++) {
		Handler *h = new Handler;
		h->start();
		handlers << h;
	}

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
	exit(app.exec());
}

void finish(int) {
	foreach(pid_t pid, children)
		kill(pid, SIGTERM);
	exit(1);
}

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	tcount = QThread::idealThreadCount();
	if (tcount < 1)
		tcount = 1;

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	c(sock, "socket");
	int on = 1;
	c(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), "reuseaddress");
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof addr);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(QCoreApplication::arguments()[3].toInt());
	c(bind(sock, static_cast<sockaddr *>(static_cast<void *>(&addr)), sizeof addr), "bind");
	c(listen(sock, 50), "listen");
	if (QCoreApplication::arguments().count() == 6 && QCoreApplication::arguments().at(5) == "compress") {
		Connection::enableCompression = true;
	}
	for (int *sig = sigs; *sig; sig ++) {
		struct sigaction action;
		memset(&action, 0, sizeof action);
		action.sa_handler = finish;
		action.sa_flags = SA_RESETHAND;
		c(sigaction(*sig, &action, NULL), "sigaction");
	}
	for (int i = 0; i < tcount; i ++)
		doFork(app);
	for (;;) {
		int status;
		pid_t pid = wait(&status);
		if (pid == -1 && errno == EINTR)
			continue;
		c(pid, "wait");
		children.remove(pid);
		doFork(app);
	}
	return app.exec();
}
