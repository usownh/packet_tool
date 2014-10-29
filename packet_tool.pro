#-------------------------------------------------
#
# Project created by QtCreator 2013-10-25T22:20:39
#
#-------------------------------------------------

QT       += core gui
QT       += network

TARGET = packet_tool
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    dialogbeforecap.cpp \
    capture.cpp \
    packet.cpp

HEADERS  += mainwindow.h \
    dialogbeforecap.h \
    capture.h \
    packet.h

FORMS    += mainwindow.ui \
    dialogbeforecap.ui
LIBS += Packet.lib \
    wpcap.lib \
