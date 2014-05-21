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
