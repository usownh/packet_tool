#ifndef DIALOGBEFORECAP_H
#define DIALOGBEFORECAP_H

#include <QDialog>
#include <include/pcap.h>
#include <QDebug>
#include <QByteArray>
#include <QHostAddress>
#include <QSettings>
#include <QString>
#include <QStandardItemModel>



namespace Ui {
class DialogBeforeCap;
}

class DialogBeforeCap : public QDialog
{
    Q_OBJECT
    
public:
    explicit DialogBeforeCap(QWidget *parent = 0);
    ~DialogBeforeCap();
    void setDevice(pcap_if_t *d);
    void writeSettings();
    void readSettings();
    QString readSettingsIndex(int index);
signals:
    void startCapture();
    void filter(QString);
    
public slots:
    void on_pushButtonOk_clicked();

    void on_pushButtonCancel_clicked();

    void on_listView_clicked(const QModelIndex &index);

private slots:
    void on_listView_doubleClicked(const QModelIndex &index);

private:
    Ui::DialogBeforeCap *ui;
    pcap_if_t *currentDevice;
    QStandardItemModel *listModel;
};

#endif // DIALOGBEFORECAP_H
