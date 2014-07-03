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

#ifndef CONN_H
#define CONN_H

#include <QSslSocket>
#include <QLocalSocket>
#include <QByteArray>
#include <QSslConfiguration>
#include <QTimer>

class Connection : public QObject {
	Q_OBJECT
public:
	Connection(int socket, QSslConfiguration &config);
private:
	QSslSocket remote;
	QLocalSocket local;
	QTimer timer;
	QByteArray inBuf, outBuf;
	bool inReady, outReady;
	void touch();
private slots:
	void incoming();
	void error(QAbstractSocket::SocketError);
	void error(QLocalSocket::LocalSocketError);
	void error(const QList<QSslError> &);
	void connectedRemote();
	void tryWriteRemote();
	void outgoing();
	void connectedLocal();
	void tryWriteLocal();
};

#endif
