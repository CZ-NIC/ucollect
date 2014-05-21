#ifndef HANDLER_H
#define HANDLER_H

#include <QThread>
#include <QSslConfiguration>

class Receiver : public QObject {
	Q_OBJECT
public:
	Receiver();
private slots:
	void handleConnection(int fd);
private:
	QSslConfiguration config;
};

class Handler : public QThread {
	Q_OBJECT
public:
	Receiver *receiver;
	Handler();
	void putFd(int fd);
protected:
	virtual void run();
signals:
	void handleConnection(int fd);
};

#endif
