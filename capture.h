#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>
#include <include/pcap.h>
#include <QDebug>
#include <QList>
#include <packet.h>
#include <QByteArray>
#include <QMutex>

class Capture : public QThread
{
    Q_OBJECT
public:
    explicit Capture(QObject *parent = 0);
    void setDevice(pcap_if_t *d);
    void setPacketList(QList<Packet> *p){p->clear();packetList=p;}
    void setMutex(QMutex* m){mutex=m;}
signals:
    void newPacket();
public slots:
    void filter(QString f);
private:
    void run();
    pcap_if_t *currentDevice;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    QList<Packet> *packetList;
    Packet currentPacket;
    int packetId;
    QString filterStr;
    QMutex *mutex;
};

#endif // CAPTURE_H
