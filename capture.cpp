#include "capture.h"
#include <time.h>
Capture::Capture(QObject *parent) :
    QThread(parent)
{
    packetId=0;
}

void Capture::setDevice(pcap_if_t *d)
{
    currentDevice=d;
}

void Capture::run()
{
    /* 打开设备 */
    if ( (adhandle= pcap_open_live(currentDevice->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              1,    // 混杂模式
                              1000,             // 读取超时时间
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        qDebug()<<"设备打开失败。";
        return ;
    }
    if(filterStr!="")
    {
        struct bpf_program fcode;
        u_int netmask;
        if (currentDevice->addresses != NULL)
               /* 获取接口第一个地址的掩码 */
               netmask=((struct sockaddr_in *)(currentDevice->addresses->netmask))->sin_addr.S_un.S_addr;
           else
               /* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
               netmask=0xffffff;


      // compile the filter
        if (pcap_compile(adhandle, &fcode,filterStr.toLocal8Bit(), 1, netmask) < 0)
        {
            qDebug()<<"\nUnable to compile the packet filter. Check the syntax.\n";
            return;
        }

      // set the filter
        if (pcap_setfilter(adhandle, &fcode) < 0)
        {
            qDebug()<<"\nError setting the filter.\n";
            return;
        }
    }

    int res;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;//long

    /* 获取数据包 */
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
    {
        if(res == 0)  continue; /* 超时时间到 */
        /* 将时间戳转换成可识别的格式 */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        //qDebug()<<QString(timestr)+","<<header->ts.tv_usec<<"len:"<<header->len;

        currentPacket.setPacket(QByteArray((char*)pkt_data,header->len));
        currentPacket.setLength(header->len);
        currentPacket.time=QTime().fromString(QString(timestr),"hh:mm:ss");
        currentPacket.packetId=packetId++;
        mutex->lock();
        packetList->append(currentPacket);
        mutex->unlock();
        emit newPacket();
    }
    if(res == -1)
    {
        qDebug()<<"Error reading the packets: "+QString(pcap_geterr(adhandle));
        return;
    }

}

void Capture::filter(QString f)
{
    filterStr=f;
}











