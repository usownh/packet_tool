#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{    
    ui->setupUi(this);
    alldevs=NULL;
    this->getAllDevice();
    connect(&beforeCapOption,SIGNAL(startCapture()),this,SLOT(startCapture()));
    connect(&capThread,SIGNAL(newPacket()),this,SLOT(newPacketCaptured()));
    connect(&beforeCapOption,SIGNAL(filter(QString)),&capThread,SLOT(filter(QString)));

    ui->textBrowser->setAcceptRichText(false);
    ui->pushButtonSearch->setDisabled(true);

    treeModel = new QStandardItemModel();
    ui->treeView->setModel(treeModel);
    ui->treeView->setHeaderHidden(true);
    tableModel = new QStandardItemModel();
    tableModel->setColumnCount(6);
    tableModel->setHeaderData(0,Qt::Horizontal,QString::fromLocal8Bit("编号"));
    tableModel->setHeaderData(1,Qt::Horizontal,QString::fromLocal8Bit("已抓数据包"));
    tableModel->setHeaderData(2,Qt::Horizontal,QString::fromLocal8Bit("保存的请求包"));
    tableModel->setHeaderData(3,Qt::Horizontal,QString::fromLocal8Bit("目的地址"));
    tableModel->setHeaderData(4,Qt::Horizontal,QString::fromLocal8Bit("协议"));
    tableModel->setHeaderData(5,Qt::Horizontal,QString::fromLocal8Bit("信息"));
    ui->tableView->setModel(tableModel);
    //表头信息显示居左
    ui->tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignHCenter);
    ui->tableView->setColumnWidth(0,50);
    ui->tableView->setColumnWidth(1,300);
    ui->tableView->setColumnWidth(2,300);
    ui->tableView->setColumnWidth(3,10);
    ui->tableView->setColumnWidth(4,10);
    ui->tableView->setColumnWidth(5,10);
    ui->tableView->verticalHeader()->setVisible(false);
    debug.setFileName("debug.txt");
    mutex = new QMutex();
    capThread.setMutex(mutex);
}

MainWindow::~MainWindow()
{
    if(alldevs) pcap_freealldevs(alldevs);
    delete ui;
}



void MainWindow::getAllDevice()//获取设备
{

    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ui->comboBoxSelectDevice->addItem(tr("设备获取失败！"));
        ui->pushButtonStartStop->setDisabled(true);
        return;
    }

    QString tmp;
    /* 打印列表 */
    for(d= alldevs; d != NULL; d= d->next)
    {
        tmp=QString(d->name);
        if (d->description)
            tmp=tmp+QString(d->description);
        pcap_addr_t *a;
        QHostAddress add;
        for(a=d->addresses;a;a=a->next)
        {
            switch(a->addr->sa_family)
            {
              case AF_INET:
                if (a->addr)
                {
                    add.setAddress((sockaddr *)a->addr);
                    tmp=tmp+"{"+add.toString()+"}";
                }
              default:;
            }
        }
        ui->comboBoxSelectDevice->addItem(tmp);
        i++;
    }

    if (i == 0)
    {
        ui->comboBoxSelectDevice->addItem(tr("没有找到设备接口！请确保争取安装了WinPcap"));
        ui->pushButtonStartStop->setDisabled(true);
        return;
    }
}

void MainWindow::startCapture()
{
    capThread.start();
    ui->pushButtonStartStop->setText(tr("停止抓包"));
}

void MainWindow::on_pushButtonStartStop_clicked()
{
    if(capThread.isRunning()==false)
    {
        int i=0;
        do
        {
            output.setFileName("data"+QString().setNum(i)+".txt");
            i++;
            qDebug()<<i;
        }while(output.exists());
        output.open(QIODevice::WriteOnly);
//        debug.open(QIODevice::WriteOnly);
        packetNum=0;
        toFile=0;
        d=alldevs;
        for(int i=0;i<ui->comboBoxSelectDevice->currentIndex();i++) d=d->next;
        beforeCapOption.setDevice(d);
        beforeCapOption.show();
        capThread.setDevice(d);
        capThread.setPacketList(&newPacketList);
        packetList.clear();
        ui->comboBoxSelectDevice->setDisabled(true);
    }
    else
    {
        capThread.terminate();
        while(!newPacketList.isEmpty()) this->newPacketCaptured();
        output.close();
//        debug.close();
        ui->pushButtonStartStop->setText(tr("开始抓包"));
        ui->comboBoxSelectDevice->setEnabled(true);
        ui->pushButtonSearch->setEnabled(true);
    }
}

void MainWindow::newPacketCaptured()
{
    //qDebug()<<newPacketList.first().ipVersion();
//    qDebug()<<"new:"<<newPacketList.size();
//    if(newPacketList.size()==0) return;
    mutex->lock();
    packetList.append(newPacketList.first());
    newPacketList.removeFirst();
    mutex->unlock();
//    this->addPacket2Table(packetNum);
    this->add2File();
//    ui->tableView->selectRow(packetNum);
    packetNum++;
    tableModel->setItem(0,1,new QStandardItem("packet captured:"+QString().setNum(packetNum)));
}
void MainWindow::add2File()
{
//    qDebug()<<"add2:"<<packetList.size();
    currentPacket=packetList.first();
    QString tmp;
    if(currentPacket.protocolStr.contains("TCP"))
    {
        QString txt=QString(currentPacket.packet.mid(currentPacket.tcpendP,currentPacket.totalLength()-currentPacket.tcpendP));
        if(txt.startsWith("GET")||txt.startsWith("POST"))
        {
            tmp=txt.mid(3,txt.indexOf("HTTP")-3);
            if(txt.contains("Referer:"))
            {
                tmp=txt.mid(txt.indexOf("Referer:")+8,txt.indexOf("\n",txt.indexOf("Referer:"))-txt.indexOf("Referer:")-10)+tmp;
            }
            else
            {
                tmp=txt.mid(txt.indexOf("Host:")+5,txt.indexOf("\n",txt.indexOf("Host:"))-txt.indexOf("Host:")-5)+tmp;
            }
            toFile++;
            tableModel->setItem(0,2,new QStandardItem("request packet saved:"+QString().setNum(toFile)));
            tmp.remove("\n");
            qDebug()<<tmp;
            tmp.remove(" ");
            tmp=currentPacket.srcIP().toString()+" "+currentPacket.time.toString()+" "+tmp;
            output.write(tmp.toLocal8Bit()+"\n");
//            debug.write("\n=========\n"+txt.toLocal8Bit());
        }
    }
    packetList.removeFirst();
}

void MainWindow::addPacket2Table(int selectNum)
{
    currentPacket=packetList.at(selectNum);
    tableModel->setItem(packetNum,0,new QStandardItem(QString().setNum(currentPacket.packetId)));
    tableModel->setItem(packetNum,1,new QStandardItem(currentPacket.time.toString()));
    tableModel->setItem(packetNum,2,new QStandardItem(currentPacket.srcIP().toString()));
    tableModel->setItem(packetNum,3,new QStandardItem(currentPacket.dstIP().toString()));
    if(currentPacket.protocolStr=="")
        tableModel->setItem(packetNum,4,new QStandardItem("port:"+QString().setNum(currentPacket.dstPort().toHex().toInt(&ok,16))));
    else
    {
        QString tmp;
        tmp=currentPacket.protocolStr;
        while(tmp.contains(","))
        {
            tmp.remove(0,tmp.indexOf(",")+1);
        }
        tableModel->setItem(packetNum,4,new QStandardItem(tmp));
    }
    if(currentPacket.protocolStr.contains("TCP"))
    {
        QString txt=QString(currentPacket.packet.mid(currentPacket.tcpendP,currentPacket.totalLength()-currentPacket.tcpendP));
        if((txt.startsWith("HTTP")||txt.startsWith("GET")||txt.startsWith("POST")||txt.startsWith("OPTIONS")||txt.startsWith("HEAD")||txt.startsWith("PUT")||txt.startsWith("DELETE")||txt.startsWith("TRACE")||txt.startsWith("CONNECT")))
        {
            tableModel->setItem(packetNum,5,new QStandardItem(txt));
        }
        else
        {
            QString tmp;
            if(currentPacket.tcpURG()) tmp+="<URG>";
            if(currentPacket.tcpACK()) tmp+="<ACK>";
            if(currentPacket.tcpPSH()) tmp+="<PSH>";
            if(currentPacket.tcpRST()) tmp+="<RST>";
            if(currentPacket.tcpSYN()) tmp+="<SYN>";
            if(currentPacket.tcpFIN()) tmp+="<FIN>";
            tmp+="Seq:"+QString(currentPacket.seqNum().toHex());
            tmp+="Ack:"+QString(currentPacket.ackNum().toHex());
            tableModel->setItem(packetNum,5,new QStandardItem(tmp));
        }
    }
    else if(currentPacket.protocolStr.contains("UDP"))
    {
        tableModel->setItem(packetNum,5,new QStandardItem( QString(currentPacket.packet.mid(currentPacket.udpendP,currentPacket.totalLength()-currentPacket.udpendP))));
    }
    else if(currentPacket.protocolStr.contains("IP"))
    {
        tableModel->setItem(packetNum,5,new QStandardItem( QString(currentPacket.packet.mid(currentPacket.ipendP,currentPacket.totalLength()-currentPacket.ipendP)) ));
    }
    else
    {
        tableModel->setItem(packetNum,5,new QStandardItem( QString(currentPacket.packet.toHex() ) ));
    }

}

void MainWindow::addPacket2Tree(int selectNum)
{
    int i=0;
    currentPacket=packetList.at(selectNum);
    treeModel->clear();
    QStandardItem *frameItem = new QStandardItem(tr("帧 ")+QString("%0: %1").arg(currentPacket.packetId).arg(currentPacket.length())+tr(" 字节捕获"));
    QStandardItem *time=new QStandardItem(tr("捕获时间：")+currentPacket.time.toString());
    QStandardItem *protocol=new QStandardItem(tr("协议：")+currentPacket.protocolStr);
    frameItem->appendRow(time);
    frameItem->appendRow(protocol);
    treeModel->setItem(i++,frameItem);

    QStandardItem *mac=new QStandardItem(tr("以太网帧：源地址：")+currentPacket.srcMac().toHex()+tr("目的地址：")+currentPacket.dstMac().toHex());
    QString tmp;
    if(currentPacket.protocolStr.contains("IP")) tmp="IP";
    else if(currentPacket.protocolStr.contains("ARP")) tmp="IP";
    else tmp=tr("其他");
    QStandardItem *type=new QStandardItem(tr("协议类型：")+tmp);
    mac->appendRow(type);
    treeModel->setItem(i++,mac);

    if(currentPacket.protocolStr.contains("IP"))
    {
        QStandardItem *ip=new QStandardItem(tr("IP协议:源地址：")+currentPacket.srcIP().toString()+tr("目的地址：")+currentPacket.dstIP().toString());
        QString tmp;
        if(currentPacket.ipVersion()==4) tmp="4";
        if(currentPacket.ipVersion()==6) tmp="6";
        QStandardItem *version=new QStandardItem(tr("版本：")+tmp);
        ip->appendRow(version);
        QStandardItem *headerLength=new QStandardItem(tr("IP头长：")+tmp.setNum(currentPacket.ipHeaderLength())+tr("字节"));
        ip->appendRow(headerLength);
        QStandardItem *totalLength=new QStandardItem(tr("总长度：")+tmp.setNum(currentPacket.totalLength())+tr("字节"));
        ip->appendRow(totalLength);
        QStandardItem *ID=new QStandardItem(tr("标识：")+currentPacket.id().toHex());
        ip->appendRow(ID);
        tmp=tr("保留位：@；还有分片：#；不能分片：$");
        if(currentPacket.reservedBit()) tmp.replace("@",tr("已设置"));
        else tmp.replace("@",tr("未设置"));
        if(currentPacket.moreFragment()) tmp.replace("#",tr("已设置"));
        else tmp.replace("#",tr("未设置"));
        if(currentPacket.dontFragment()) tmp.replace("$",tr("已设置"));
        else tmp.replace("$",tr("未设置"));
        QStandardItem *flags=new QStandardItem(tmp);
        ip->appendRow(flags);
        QStandardItem *offset=new QStandardItem(tr("片偏移：")+tmp.setNum(currentPacket.offset(),16));
        ip->appendRow(offset);
        QStandardItem *ttl=new QStandardItem(tr("生存时间：")+tmp.setNum(currentPacket.ttl()));
        ip->appendRow(ttl);
        if(currentPacket.protocol()==6) tmp="TCP";
        if(currentPacket.protocol()==17) tmp="UDP";
        QStandardItem *protocolInIp=new QStandardItem(tr("协议：")+tmp);
        ip->appendRow(protocolInIp);
        treeModel->setItem(i++,ip);
    }
    if(currentPacket.protocolStr.contains("ARP"))
    {
    }
    if(currentPacket.protocolStr.contains("TCP"))
    {
        QStandardItem *tcp=new QStandardItem(tr("TCP协议:源端口：")+tmp.setNum(currentPacket.srcPort().toHex().toInt(&ok,16))+tr("目的端口：")+tmp.setNum(currentPacket.dstPort().toHex().toInt(&ok,16)));
        QStandardItem *seqNum=new QStandardItem(tr("序列号：")+currentPacket.seqNum().toHex());
        tcp->appendRow(seqNum);
        QStandardItem *ackNum=new QStandardItem(tr("确认号：")+currentPacket.ackNum().toHex());
        tcp->appendRow(ackNum);
        QStandardItem *headLength=new QStandardItem(tr("tcp头长：")+tmp.setNum(currentPacket.tcpHeaderLength()));
        tcp->appendRow(headLength);

        tmp=tr("URG：@；ACK：#；PSH：$；RST：%；SYN：^；FIN：&");
        if(currentPacket.tcpURG()) tmp.replace("@",tr("已设置"));
        else tmp.replace("@",tr("未设置"));
        if(currentPacket.tcpACK()) tmp.replace("#",tr("已设置"));
        else tmp.replace("#",tr("未设置"));
        if(currentPacket.tcpPSH()) tmp.replace("$",tr("已设置"));
        else tmp.replace("$",tr("未设置"));
        if(currentPacket.tcpRST()) tmp.replace("%",tr("已设置"));
        else tmp.replace("%",tr("未设置"));
        if(currentPacket.tcpSYN()) tmp.replace("^",tr("已设置"));
        else tmp.replace("^",tr("未设置"));
        if(currentPacket.tcpFIN()) tmp.replace("&",tr("已设置"));
        else tmp.replace("&",tr("未设置"));
        QStandardItem *flags=new QStandardItem(tmp);
        tcp->appendRow(flags);

        QStandardItem *window=new QStandardItem(tr("tcp窗口：")+tmp.setNum(currentPacket.tcpWindow()));
        tcp->appendRow(window);
        treeModel->setItem(i++,tcp);
    }
    if(currentPacket.protocolStr.contains("UDP"))
    {
        QStandardItem *udp=new QStandardItem(tr("UDP协议:源端口：")+tmp.setNum(currentPacket.srcPort().toHex().toInt(&ok,16))+tr("目的端口：")+tmp.setNum(currentPacket.dstPort().toHex().toInt(&ok,16)));
        QStandardItem *length=new QStandardItem(tr("长度：")+tmp.setNum(currentPacket.udpLength()));
        udp->appendRow(length);
        QStandardItem *checkSum=new QStandardItem(tr("校验和：")+currentPacket.udpCheckSum().toHex());
        udp->appendRow(checkSum);
        treeModel->setItem(i++,udp);
    }
    QString txt=QString(currentPacket.packet.mid(currentPacket.tcpendP,currentPacket.totalLength()-currentPacket.tcpendP));
    if((txt.contains("HTTP",Qt::CaseInsensitive)||txt.startsWith("GET")||txt.startsWith("POST")||txt.startsWith("OPTIONS")||txt.startsWith("HEAD")||txt.startsWith("PUT")||txt.startsWith("DELETE")||txt.startsWith("TRACE")||txt.startsWith("CONNECT")))
    {
        QStandardItem *http=new QStandardItem(tr("HTTP协议："));
        while(!txt.isEmpty()&&txt.contains("\r\n"))
        {

            QStandardItem *item=new QStandardItem(txt.mid(0,txt.indexOf("\r\n")));
            txt.remove(0,txt.indexOf("\r\n")+2);
            http->appendRow(item);
        }
        if(!txt.isEmpty())
        {
            QStandardItem *item=new QStandardItem(txt);
            http->appendRow(item);
        }
        treeModel->setItem(i++,http);
    }


}

void MainWindow::addPacket2Text(int selectNum)
{
    ui->textBrowser->clear();
    ui->textBrowser->setFontPointSize(18);
    currentPacket=packetList.at(selectNum);
    int i;
    QString lineNum,line,txt,tmp;
    for(i=0;i<currentPacket.length()-16;i=i+16)
    {
        lineNum.setNum(i,16);
        for(;lineNum.length()<4;) lineNum="0"+lineNum;
        line=lineNum;
        line+="\t";
        for(int j=0;j<16;j++) line=line+currentPacket.packet.mid(i+j,1).toHex()+" ";
        txt=QString(currentPacket.packet.mid(i,16));
        tmp="\\";
        txt.replace(tmp,tmp+tmp);
        txt.replace("\r",".");
        txt.replace("\n",".");
        line=line+"\t"+txt;
        ui->textBrowser->append(line);
    }
    lineNum.setNum(i,16);
    for(;lineNum.length()<4;) lineNum="0"+lineNum;
    line=lineNum;
    line+="\t";
    int t;
    t=currentPacket.length()-i;
    for(int j=0;j<t;j++) line=line+currentPacket.packet.mid(i+j,1).toHex()+" ";
    for(int j=t;j<16;j++) line=line+"   ";
    txt=QString(currentPacket.packet.mid(i,16));
    tmp="\\";
    txt.replace(tmp,tmp+tmp);
    line=line+"\t"+txt;
    txt.replace("\r",".");
    txt.replace("\n",".");
    ui->textBrowser->append(line);
}

void MainWindow::on_tableView_clicked(const QModelIndex &index)
{
    int num=tableModel->itemFromIndex(tableModel->index(index.row(),0))->text().toInt();
    addPacket2Text(num);
    addPacket2Tree(num);
}

void MainWindow::on_pushButtonSearch_clicked()
{
    QString searchStr=ui->lineEdit->text();
    if(searchStr.startsWith("srcip"))
    {
        qDebug()<<tableModel->rowCount();
        for(int i=0;i<tableModel->rowCount();i++)
        {
            QString srcip=tableModel->itemFromIndex(tableModel->index(i,2))->text();
            searchStr.remove("srcip");
            searchStr=searchStr.trimmed();
            if(srcip!=searchStr) tableModel->removeRow(i--);
        }
    }
    else if(searchStr.startsWith("dstip"))
    {
        for(int i=0;i<tableModel->rowCount();i++)
        {
            QString dstip=tableModel->itemFromIndex(tableModel->index(i,3))->text();
            searchStr.remove("dstip");
            searchStr=searchStr.trimmed();
            if(dstip!=searchStr) tableModel->removeRow(i--);
        }
    }
    else if(searchStr.startsWith("srcport"))
    {
        for(int i=0;i<tableModel->rowCount();i++)
        {
            int num=tableModel->itemFromIndex(tableModel->index(i,0))->text().toInt();
            currentPacket=packetList.at(num);
            QString port=QString(currentPacket.srcPort().toHex());
            searchStr.remove("srcport");
            searchStr=searchStr.trimmed();
            if(port.toInt(&ok,16)!=searchStr.toInt()) tableModel->removeRow(i--);
        }
    }
    else if(searchStr.startsWith("dstport"))
    {
        for(int i=0;i<tableModel->rowCount();i++)
        {
            int num=tableModel->itemFromIndex(tableModel->index(i,0))->text().toInt();
            currentPacket=packetList.at(num);
            QString port=QString(currentPacket.dstPort().toHex());
            searchStr.remove("dstport");
            searchStr=searchStr.trimmed();
            if(port.toInt(&ok,16)!=searchStr.toInt()) tableModel->removeRow(i--);
        }
    }
    else if(searchStr.startsWith("strsearch"))
    {
        for(int i=0;i<tableModel->rowCount();i++)
        {
            int num=tableModel->itemFromIndex(tableModel->index(i,0))->text().toInt();
            currentPacket=packetList.at(num);
            searchStr.remove("strsearch");
            searchStr=searchStr.trimmed();
            if(!currentPacket.packet.contains(searchStr.toLocal8Bit())) tableModel->removeRow(i--);
        }
    }
    else
        ui->lineEdit->setText(tr("不能识别的命令"));


}
