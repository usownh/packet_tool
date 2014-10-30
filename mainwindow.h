#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <include/pcap.h>
#include <QString>
#include <QDebug>
#include <dialogbeforecap.h>
#include <capture.h>
#include <QTime>
#include <QList>
#include <QHostAddress>
#include <packet.h>
#include <QStandardItemModel>
#include <QFile>
#include <QMutex>

namespace Ui {
class MainWindow;
}



class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void addPacket2Table(int selectNum);
    void addPacket2Tree(int selectNum);
    void addPacket2Text(int selectNum);
    void add2File();
public slots:
    void startCapture();
    void newPacketCaptured();
private slots:
    void on_pushButtonStartStop_clicked();


    void on_tableView_clicked(const QModelIndex &index);

    void on_pushButtonSearch_clicked();

private:
    void getAllDevice();

    pcap_if_t *alldevs;
    pcap_if_t *d;

    DialogBeforeCap beforeCapOption;
    Capture capThread;
    QList<Packet> newPacketList,packetList;
    Packet currentPacket;
    QStandardItemModel *tableModel,*treeModel;
    int packetNum,toFile;
    bool ok;
    Ui::MainWindow *ui;
    QFile output,debug;
    QMutex *mutex;
};

#endif // MAINWINDOW_H
