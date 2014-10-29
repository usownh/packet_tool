#include "packet.h"

Packet::Packet()
{
}
void Packet::setPacket(QByteArray b)
{
    packet=b;
    if(this->type().toHex()=="0800")    protocolStr="IP";
    else if(this->type().toHex()=="0806")   protocolStr="ARP";
    if(this->protocol()==0x06)
    {
        protocolStr+=",TCP";
        ipendP=14+this->ipHeaderLength();
        tcpendP=ipendP+this->tcpHeaderLength();
    }
    else if(this->protocol()==0x11)
    {
        protocolStr+=",UDP";
        ipendP=14+this->ipHeaderLength();
        udpendP=ipendP+8;
    }
}

qint8 Packet::ipVersion()
{
    qint8 version;
    version=packet.at(14)&0xf0;
    version=version>>4;
    return version;
}

qint8 Packet::ipHeaderLength()
{
    qint8 headLength;
    headLength=packet.at(14)&0x0f;
    return headLength*4;
}
qint8 Packet::ds()//区分服务
{
    return packet.at(15);
}
int Packet::totalLength()
{
    return packet.mid(16,2).toHex().toInt(&ok,16);
    QString tmp;
    tmp=packet.mid(17,1).toHex()+packet.mid(16,1).toHex();
    return tmp.toInt(&ok,16);
}
QByteArray Packet::id()
{
    return packet.mid(18,2);
}
bool Packet::reservedBit()
{
    if(packet.at(20)&0x80)   return true;
    else return false;
}
bool Packet::dontFragment()
{
    if(packet.at(20)&0x40)   return true;
    else return false;
}
bool Packet::moreFragment()
{
    if(packet.at(20)&0x20)   return true;
    else return false;
}
int Packet::offset()
{
    int offsetL=packet.mid(20,2).toHex().toInt(&ok,16)&0x1f;
    return offsetL;
}
qint8 Packet::ttl()
{
    return packet.at(22);
}
qint8 Packet::protocol()
{
    return packet.at(23);
}
QByteArray Packet::checkSum()
{
    return packet.mid(24,2);
}
QHostAddress Packet::srcIP()
{
    QHostAddress ip;
    QString tmp;
    tmp=QString().setNum((uint8_t)packet.at(26))+"."+QString().setNum((uint8_t)packet.at(27))+"."
            +QString().setNum((uint8_t)packet.at(28))+"."+QString().setNum((uint8_t)packet.at(29));
    ip.setAddress(tmp);
    return ip;
}
QHostAddress Packet::dstIP()
{
    QHostAddress ip;
    QString tmp;
    tmp=QString().setNum((uint8_t)packet.at(30))+"."+QString().setNum((uint8_t)packet.at(31))+"."
            +QString().setNum((uint8_t)packet.at(32))+"."+QString().setNum((uint8_t)packet.at(33));
    ip.setAddress(tmp);
    return ip;
}
QByteArray Packet::srcPort()
{
    return packet.mid(ipendP,2);
}
QByteArray Packet::dstPort()
{
    return packet.mid(ipendP+2,2);
}
QByteArray Packet::seqNum()
{
    return packet.mid(ipendP+4,4);
}

QByteArray Packet::ackNum()
{

    return packet.mid(ipendP+8,4);
}

qint8 Packet::tcpHeaderLength()
{
    qint8 l;
    l=packet.at(ipendP+12)&0xf0;
    l=l>>4;
    l=l*4;
    return l;
}
bool Packet::tcpURG()
{
    if(packet.at(ipendP+13)&0x20) return true;
    else return false;
}
bool Packet::tcpACK()
{
    if(packet.at(ipendP+13)&0x10) return true;
    else return false;
}

bool Packet::tcpPSH()
{
    if(packet.at(ipendP+13)&0x08) return true;
    else return false;
}

bool Packet::tcpRST()
{
    if(packet.at(ipendP+13)&0x04) return true;
    else return false;
}
bool Packet::tcpSYN()
{
    if(packet.at(ipendP+13)&0x02) return true;
    else return false;
}
bool Packet::tcpFIN()
{
    if(packet.at(ipendP+13)&0x01) return true;
    else return false;
}
int Packet::tcpWindow()
{
    return packet.mid(ipendP+14,2).toHex().toInt(&ok,16);
    QString tmp;
    tmp=packet.mid(ipendP+15,1).toHex()+packet.mid(ipendP+14,1).toHex();
    return tmp.toInt(&ok,16);
}

int Packet::udpLength()
{
    qDebug()<<ipendP;
    qDebug()<<packet.mid(ipendP+4,2).toHex();
    return packet.mid(ipendP+4,2).toHex().toInt(&ok,16);
    QString tmp;
    tmp=packet.mid(ipendP+5,1).toHex()+packet.mid(ipendP+4,1).toHex();
    return tmp.toInt(&ok,16);
}

QByteArray Packet::udpCheckSum()
{
    return packet.mid(ipendP+6,2);
}
