#ifndef CUSTOMTHREAD_H
#define CUSTOMTHREAD_H

#include <QDebug>
#include <QThread>
#include <QDir>
#include <QFileInfo>
class customThread : public QThread
{
    Q_OBJECT
public:
    customThread();
    int countFiles(QString path);
    int getFilesCount();
    void setDirPath(QString dirPath);
    void setCustomScanList(QStringList list);
    void setCustomScanFlag(bool value){isCustomScan=value;};
protected:
    void run();
private:
    int filesCount=1;
    int dirsCount=0;
    bool isCustomScan=false;
    QString dirPath;
    QStringList customScanList;

};

#endif // CUSTOMTHREAD_H
