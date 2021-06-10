#ifndef CLEANER_H
#define CLEANER_H

#include <QDebug>
#include <QDir>
#include <QStringListModel>
#include <QThread>

class cleaner : public QThread
{
    Q_OBJECT
signals:
    void foundPath(QString path);
    void deletedPath(QString path,QString total);
public:
    explicit cleaner();
    void setScanMode(bool value);
protected:
    void run();
private:
    QDir dir;
    QStringListModel tempFilesPath;
    QStringList filesList;
    QString tempFolderPath;
    QString windowsTemp=QString("C:\\Windows\\Temp");
    bool scan=true;
    qint64 junk=0;
};

#endif // CLEANER_H
