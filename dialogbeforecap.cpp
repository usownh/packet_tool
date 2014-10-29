#include "dialogbeforecap.h"
#include "ui_dialogbeforecap.h"



DialogBeforeCap::DialogBeforeCap(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogBeforeCap)
{
    ui->setupUi(this);
    listModel = new QStandardItemModel();
    listModel->setColumnCount(1);
    listModel->setHeaderData(0,Qt::Horizontal,QString::fromLocal8Bit("过滤条件"));
    ui->listView->setModel(listModel);
    readSettings();
}

DialogBeforeCap::~DialogBeforeCap()
{
    delete ui;
}
void DialogBeforeCap::setDevice(pcap_if_t *d)
{
    currentDevice=d;
    ui->textBrowser->setText(tr("设备信息："));
    ui->textBrowser->append(tr("设备名：")+QString(d->name));
    ui->textBrowser->append(tr("设备描述：")+QString(d->description));
    ui->textBrowser->append(tr("是否是本地环回接口：")+((d->flags & PCAP_IF_LOOPBACK)?tr("是"):tr("否")));

      /* IP 地址 */
    pcap_addr_t *a;
    QHostAddress add;
    for(a=d->addresses;a;a=a->next)
    {
        switch(a->addr->sa_family)
        {
          case AF_INET:
             ui->textBrowser->append(tr("IPv4："));
            if (a->addr)
            {
                add.setAddress((sockaddr *)a->addr);
                ui->textBrowser->append(tr("IP地址：")+add.toString());
            }
            if (a->netmask)
            {
                add.setAddress((sockaddr *)a->netmask);
                ui->textBrowser->append(tr("子网掩码：")+add.toString());
            }
            if (a->broadaddr)
            {
                add.setAddress((sockaddr *)a->broadaddr);
                ui->textBrowser->append(tr("广播地址：")+add.toString());
            }
            break;

          case AF_INET6:
            ui->textBrowser->append(tr("IPv6："));
            if (a->addr)
            {
                add.setAddress((sockaddr *)a->addr);
                ui->textBrowser->append(tr("IP地址：")+add.toString());
            }
           break;

          default:;
        }
    }
}


void DialogBeforeCap::on_pushButtonOk_clicked()
{
    emit filter(ui->lineEdit->text());
    emit startCapture();
    this->close();
}


void DialogBeforeCap::writeSettings()
{
    QSettings settings("config.ini",QSettings::IniFormat);
    settings.beginGroup("FILTER");
    QString tmp;
    int i=0;
    for(;i<10;i++) settings.setValue("Filter"+tmp.setNum(i),"a,a");
    settings.endGroup();
}

void DialogBeforeCap::readSettings()
{
    QSettings settings("config.ini",QSettings::IniFormat);
    settings.beginGroup("FILTER");
    QString tmpNum,tmp;
    int i=0;
    while(true)
    {
        tmp=settings.value("Filter"+tmpNum.setNum(i)).toString();
        if(tmp=="") break;
        listModel->setItem(i,0,new QStandardItem(tmp.mid(0,tmp.indexOf(","))));
        i++;
    }
    settings.endGroup();
}

QString DialogBeforeCap::readSettingsIndex(int index)
{
    QSettings settings("config.ini",QSettings::IniFormat);
    settings.beginGroup("FILTER");
    QString tmpNum,tmp;
    tmp=settings.value("Filter"+tmpNum.setNum(index)).toString();
    settings.endGroup();
    return tmp.mid(tmp.indexOf(",")+1,tmp.length()-tmp.indexOf(",")-1);
}

void DialogBeforeCap::on_pushButtonCancel_clicked()
{
    this->close();
}

void DialogBeforeCap::on_listView_clicked(const QModelIndex &index)
{
    ui->lineEdit->setText(this->readSettingsIndex(index.row()));
}

void DialogBeforeCap::on_listView_doubleClicked(const QModelIndex &index)
{
    ui->lineEdit->setText(this->readSettingsIndex(index.row()));
    this->on_pushButtonOk_clicked();
}
