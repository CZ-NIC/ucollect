TEMPLATE = app
TARGET = soxy
DEPENDPATH += .
INCLUDEPATH += .

# Input
SOURCES += main.cpp
HEADERS += handler.h conn.h
QT += network
QT -= gui
