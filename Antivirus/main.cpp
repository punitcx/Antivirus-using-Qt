#include "mainscreen.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    int exitcode;
    do{
    mainScreen w;
    a.setQuitOnLastWindowClosed(false);
    a.setApplicationName("Avaxi Antivirus");
    a.setApplicationDisplayName("Avaxi Antivirus");
    a.setApplicationVersion("0.1.0");
    w.setWindowIcon(QIcon(":/avaxi.png"));
    w.setWindowTitle(a.applicationName()+QString(" V%1 ").arg(a.applicationVersion()));
    w.show();
    exitcode=a.exec();
    }
    while(exitcode==4444);
    return exitcode;
}
