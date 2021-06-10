#include "cleaner.h"

cleaner::cleaner()
{
    tempFolderPath=QString(qgetenv("TEMP"));
    dir.setPath(tempFolderPath);
    dir.setFilter(QDir::NoDotAndDotDot|QDir::AllEntries|QDir::Hidden);
}

void cleaner::setScanMode(bool value)
{
    scan=value;
}

void cleaner::run()
{
    if(scan)
    {
    dir.setPath(tempFolderPath);
    filesList=dir.entryList();
    foreach(QString dirPath, filesList)
    {
        qDebug()<<"Directory Path: "<<dirPath;
        emit foundPath(dir.absoluteFilePath(dirPath).replace("/","\\"));
    }

    dir.setPath(windowsTemp);
    filesList=dir.entryList();
    foreach(QString dirPath, filesList)
    {
        qDebug()<<"Directory Path: "<<dirPath;
        emit foundPath(dir.absoluteFilePath(dirPath).replace("/","\\"));
    }
    }

    else
    {
        junk=0;
        QString unit=" bytes";
        dir.setPath(tempFolderPath);
        filesList=dir.entryList();
        foreach(QString dirPath, filesList)
        {
            QString path=dir.absoluteFilePath(dirPath);
            QFileInfo info(path);
            if(info.isFile()){
                qDebug()<<"Deleted: "<<dirPath<<dir.remove(dirPath)<<info.size();
                junk+=info.size();
            }
            else if(info.isDir())
                qDebug()<<"Deleted: "<<dirPath<<QDir(dir.absoluteFilePath(dirPath)).removeRecursively()<<info.size();

            if(junk>1024*1024){
                junk/=(1024.0*1024.0);
                unit=" MB+";
            }
            else if(junk > 1024){
                junk/=1024.0;
                unit=" KB+";
            }


            emit deletedPath(dir.absoluteFilePath(dirPath).replace("/","\\"),QString::number(junk)+unit);
        }

        dir.setPath(windowsTemp);
        filesList=dir.entryList();
        foreach(QString dirPath, filesList)
        {
            QString path=dir.absoluteFilePath(dirPath);
            QFileInfo info(path);
            if(info.isFile()){
                qDebug()<<"Deleted: "<<dirPath<<dir.remove(dirPath)<<info.size();
                junk+=info.size();
            }
            else if(info.isDir())
                qDebug()<<"Deleted: "<<dirPath<<QDir(dir.absoluteFilePath(dirPath)).removeRecursively()<<info.size();

            if(junk>1024*1024){
                junk/=(1024.0*1024.0);
                unit=" MB+";
            }
            else if(junk > 1024){
                junk/=1024.0;
                unit=" KB+";
            }


            emit deletedPath(dir.absoluteFilePath(dirPath).replace("/","\\"),QString::number(junk)+unit);
        }
    }

}

