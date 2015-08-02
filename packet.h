#ifndef PACKET_H
#define PACKET_H

#include <QObject>
#include <QTime>
#include <QByteArray>
#include <QString>
#include <QHostAddress>
typedef unsigned char uint8_t;
class Packet
{
public:
    explicit Packet();
    void setPacket(QByteArray b);
    QByteArray srcMac(){return packet.mid(6,6);}
    QByteArray dstMac(){return packet.mid(0,6);}
    QByteArray type(){return packet.mid(12,2);}
    int length(){return packetLength;}
    void setLength(int l){packetLength=l;}
    qint8 ipVersion();
    qint8 ipHeaderLength();
    qint8 ds();//区分服务
    int totalLength();
    QByteArray id();
    bool reservedBit();
    bool dontFragment();
    bool moreFragment();
    int offset();
    qint8 ttl();
    qint8 protocol();
    QByteArray checkSum();
    QHostAddress srcIP();
    QHostAddress dstIP();
    QByteArray tcpSegment();
    QByteArray udpSegment();
    //tcp
    QByteArray srcPort();
    QByteArray dstPort();
    QByteArray seqNum();
    QByteArray ackNum();
    qint8 tcpHeaderLength();
    bool tcpURG();
    bool tcpACK();
    bool tcpPSH();
    bool tcpRST();
    bool tcpSYN();
    bool tcpFIN();
    int tcpWindow();
    //udp
    int udpLength();
    QByteArray udpCheckSum();


    
signals:
    
public slots:
public:
    QTime time;
    int packetId;
    QByteArray packet;
    QString protocolStr;
    int ipendP;
    int tcpendP;
    int udpendP;
    bool ok;
    int packetLength;
};


#endif // PACKET_H
