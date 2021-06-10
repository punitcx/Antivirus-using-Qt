#include "customthread.h"

customThread::customThread()
{

}

int customThread::countFiles(QString path)
{
    QFileInfo finfo(path);

    if(finfo.isFile())
    {
        filesCount++;
        return 0;
    }
    else if(finfo.isDir())
    {

    QStringList slist = QDir(path).entryList(QDir::AllEntries|QDir::NoSymLinks|QDir::Hidden|QDir::NoDotAndDotDot);
    foreach(QString name, slist){
        QString fullPath=path+"\\"+name;
        QFileInfo childInfo(fullPath);

    if(childInfo.isDir()){
        dirsCount++;
        countFiles(fullPath);
            }
      else{
        filesCount++;
            }
        }

    }



    qDebug()<<"Current Files Count: "<<filesCount;
    return filesCount;
}

int customThread::getFilesCount()
{
    if(filesCount)
        return filesCount;
    return 1;
}

void customThread::setDirPath(QString dirPath)
{
    this->dirPath=dirPath;
}

void customThread::setCustomScanList(QStringList list)
{
    this->customScanList=list;
}

void customThread::run()
{
    filesCount=0;
    if(isCustomScan)
    {
    foreach(QString dirpath,customScanList)
        qDebug()<<countFiles(dirpath);
    }
    else
        countFiles(dirPath);
}
