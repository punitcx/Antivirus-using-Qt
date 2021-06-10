#include "mainscreen.h"
#include "ui_mainscreen.h"

mainScreen::mainScreen(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::mainScreen)
{
    ui->setupUi(this);

    adjustLayouts();

    killClamd();

    setTrayIcon();

    allocateObjects();

    showEngineInformation();
    setWindowFlags(windowFlags()|Qt::FramelessWindowHint);

    //    player->setMedia(QUrl("C:\\Users\\Green\\Desktop\\Projects\\Antivirus\\allsounds.wav"));
//    player->setPosition(6000);
//    player->play();

    doInitialization();

    ui->stackedDisplay->setCurrentIndex(0);
    ui->statusDisplay->setCurrentIndex(0);

    startClamdInstance();

    doStartupAnimation();
}

mainScreen::~mainScreen()
{
    delete ui;
}
void mainScreen::doStartupAnimation()
{
    hide();
    animation = new startupAnimation();
    animation->showAnimation();
    animation->hideLabel();
    showNormal();
}

void mainScreen::mousePressEvent(QMouseEvent *event) {
    int loc=ui->headerFrame->pos().y()+ui->headerFrame->height();
    if(event->y()>loc)
    {flag=0; return;}
    flag=1;
    m_nMouseClick_X_Coordinate = event->x();
    m_nMouseClick_Y_Coordinate = event->y();
}

void mainScreen::mouseMoveEvent(QMouseEvent *event) {
    if(flag)
    move(event->globalX()-m_nMouseClick_X_Coordinate,event->globalY()-m_nMouseClick_Y_Coordinate);
}

void mainScreen::adjustLayouts()
{
    centralWidget()->layout()->setContentsMargins(0,0,0,0);
    statusBar()->setStyleSheet("QStatusBar{ border-bottom: 2px solid grey; border-radius: 1px; }");
    statusBar()->setFixedHeight(20);
    setWindowOpacity(0.97);
}

void mainScreen::allocateObjects()
{
    player = new QMediaPlayer(this);
    timer=new QTimer(this);
    databaseUpdateTimer = new QTimer(this);
    databaseLabel=new QLabel("");
    statusBar()->addPermanentWidget(databaseLabel);
    clamd = new clamdProcess;
    clamdscan = new clamdscanProcess;
    clamscan = new clamscanProcess;
    freshclam = new freshclamProcess;
    tempCleaner = new cleaner;
}

void mainScreen::killClamd()
{
    QProcess p;

    p.start("taskkill /F /IM clamd.exe /T");
    p.waitForFinished();

    p.close();
}

void mainScreen::doInitialization()
{
    filesCounter = new customThread;
    connect(filesCounter,SIGNAL(started()),this,SLOT(filesCounterStarted()));
    connect(databaseUpdateTimer,SIGNAL(timeout()),this,SLOT(showEngineInformation()));

    databaseUpdateTimer->start(120*60*1000);
    timer->setInterval(1000);

    ui->scanItemsView->setModel(&scanItemsListModel);
    ui->junkFilesView->setModel(&tempFilesPath);
    ui->speedupView->setModel(&speedupModel);
    scanItemsListModel.setStringList(scanItemsList);


    QDir dirCreator;
    if(!dirCreator.exists(quarantineDir))
        dirCreator.mkdir(quarantineDir);
}

QStringList mainScreen::buildArguments(QString fromFile="-f %1",QString wait="-w", QString log="-l %1",QString action="",QString multiscan=" -m")
{
    QStringList arguments;
    arguments.append(wait);
    arguments.append(fromFile.arg(scanItemsFileName));
    arguments.append(log.arg(QDir(qApp->applicationDirPath()).absoluteFilePath(logFileName)));
    if(defaultAction=="move" | defaultAction=="copy")
        action=tr("--%1=%2").arg(defaultAction,quarantineDir);
    else if(defaultAction=="delete")
        action="--remove";
    arguments.append(action);

    return arguments;


}

QStringList mainScreen::buildArguments(bool notCustom,QString dirName="C:\\", QString wait="-w", QString log="-l %1", QString action="")
{
    QStringList arguments;
    arguments.append(wait);
    arguments.append(dirName);
    arguments.append(log.arg(logFileName));
    if(defaultAction=="move" | defaultAction=="copy")
        action=tr("--%1=%2").arg(defaultAction,quarantineDir);
    else if(defaultAction=="delete")
        action="--remove";
    arguments.append(action);

    arguments.append("-a");

    return arguments;
}

void mainScreen::writeDatabaseConfiguration()
{
    QFile rawDatabase(QDir(qApp->applicationDirPath()).absoluteFilePath("rawclamd.conf"));
    QFile database(QDir(qApp->applicationDirPath()).absoluteFilePath("clamd.conf"));

    rawDatabase.open(QIODevice::ReadOnly);
    database.open(QIODevice::WriteOnly);

    QString configuration=rawDatabase.readAll();

    configuration=configuration.replace("#ExcludePath","#ExcludePath"+excludeFilesRegex);
//    ui->logViewer->setText(configuration);

    database.write(configuration.toUtf8());

}

void mainScreen::startClamdInstance()
{
    connect(clamd,SIGNAL(started()),this,SLOT(clamdStarted()),Qt::UniqueConnection);
    connect(clamd,SIGNAL(errorOccurred(QProcess::ProcessError)),this,SLOT(handleClamdProcessError(QProcess::ProcessError)),Qt::UniqueConnection);
    connect(clamd,SIGNAL(readyReadStandardOutput()),this,SLOT(readClamdOutput()),Qt::UniqueConnection);
    connect(clamd,SIGNAL(readyReadStandardError()),this,SLOT(showClamdOutputAsStatus()),Qt::UniqueConnection);

    clamd->setProgram("clamd.exe");
    clamd->setArguments(QStringList());
    qDebug()<<"clamd service starting..";
    clamd->start();
}

void mainScreen::clamdStarted()
{

    qDebug()<<"clamd service started..Waiting for output";
}

void mainScreen::handleClamdProcessError(QProcess::ProcessError error)
{
    qDebug()<<"Error"<<clamd->errorString();
}

void mainScreen::readClamdOutput()
{
    QString superRaw=QString(clamd->readAllStandardOutput().replace("\n","#").simplified());

    foreach(QString raw,superRaw.split("#",QString::SkipEmptyParts)){
//    qDebug()<<raw;

    QStringList outputList=raw.split(':',QString::SkipEmptyParts);
    qDebug()<<"Standard Output clamd: "<<outputList;

    QString root,filename,middle,last;

    if(!outputList.isEmpty())
        root=outputList.first();

    QStringList temp;
    if(outputList.length()>=2)
        temp=outputList.at(1).split("\\");
    if(!temp.isEmpty())
        filename=temp.takeLast();

    middle=temp.join("\\");

    if(!outputList.isEmpty())
        last=outputList.last();


    if(raw.isEmpty() || raw.contains("Limits") || !raw.contains("\\")|| !scanningStarted)
        return;


    QString malwareType;
    if(last.contains("FOUND"))
    {
        showTrayMessage(applicationName,root+":"+middle.mid(0,20)+"...\\"+filename+"\n"+last,1000);
        last.remove("FOUND");
        malwareType=last;
        ui->threatsDetectedLabel->setText("<font color=red>"+QString::number(++threats)+"</font>");
    }

    ui->filesScannedLabel->setText(QString::number(++filesScanned));
    ui->scanningProgressbar->setMaximum(filesCounter->getFilesCount());
    ui->scanningProgressbar->setValue(filesScanned);

    QString folderPath=root+":"+middle;
    QString displayString=folderPath;
    ui->currentFolderLabel->setToolTip(folderPath);

    if(displayString.length()>150)
        displayString=displayString.mid(0,150)+"...";
    ui->currentFolderLabel->setText(""+displayString);

    ui->currentFileLabel->setToolTip(filename);
    ui->currentFileLabel->setText(filename);

    }
}

void mainScreen::startClamdscan(QStringList arguments)
{
    if(!clamd->isOpen())
        startClamdInstance();

    if(clamdscan->isOpen())
        clamdscan->close();


    if(customFinished)
    {
    filesScanned=0;
    threats=0;
    }

    setDefaultActionText();

    connect(clamdscan,SIGNAL(started()),this,SLOT(clamdscanStarted()),Qt::UniqueConnection);
    connect(clamdscan,SIGNAL(errorOccurred(QProcess::ProcessError)),this,SLOT(handleClamdscanProcessError(QProcess::ProcessError)),Qt::UniqueConnection);
    connect(clamdscan,SIGNAL(readyReadStandardOutput()),this,SLOT(readClamdscanOutput()),Qt::UniqueConnection);
    connect(timer,SIGNAL(timeout()),this,SLOT(updateElapsedTime()),Qt::UniqueConnection);


    clamdscan->setProgram("clamdscan.exe");
    clamdscan->setArguments(arguments);
    qDebug()<<"clamdscan starting...";
    ui->stackedDisplay->setCurrentIndex(4);
    clamdscan->start();
}

void mainScreen::handleClamdscanProcessError(QProcess::ProcessError error)
{
    qDebug()<<"Error"<<clamdscan->errorString();
}

void mainScreen::readClamdscanOutput()
{
    QString superRaw=QString(clamdscan->readAllStandardOutput().replace("\n","#").simplified());

    foreach(QString raw,superRaw.split("#",QString::SkipEmptyParts)){
    qDebug()<<raw;

    if(raw.contains("SUMMARY"))
    {
        qDebug()<<"Summary Found: "<<raw.split('\n');
        ui->scanningStatus->setText("<b>Completed<b>");
        showTrayMessage("Scanning Completed",threats?"Malware Detected":"No Virus Found",4000);
        ui->lastScan->setText(QDateTime::currentDateTime().toString("dddd, MMMM dd, yyyy(hh:mm:ss)"));
        scanningStarted=false;
        stopClamdscan();
    }



    QStringList outputList=raw.split(':',QString::SkipEmptyParts);
    qDebug()<<"Standard Output clamdscan: "<<outputList;

    QString root,filename,middle,last;

    if(!outputList.isEmpty())
        root=outputList.first();

    QStringList temp;
    if(outputList.length()>=2)
        temp=outputList.at(1).split("\\");
    if(!temp.isEmpty())
        filename=temp.takeLast();

    middle=temp.join("\\");

    if(!outputList.isEmpty())
        last=outputList.last();


    if(raw.isEmpty() || raw.contains("Limits") || !scanningStarted)
        return;


    QString malwareType;
    if(last.contains("FOUND"))
    {
        showTrayMessage(applicationName,root+":"+middle.mid(0,20)+"...\\"+filename+"\n"+last,1000);
        last.remove("FOUND");
        malwareType=last;
        ui->threatsDetectedLabel->setText("<font color=red>"+QString::number(++threats)+"</font>");
    }

//    ui->filesScannedLabel->setText(QString::number(++filesScanned));

    QString folderPath=root+":"+middle;
    QString displayString=folderPath;
    ui->currentFolderLabel->setToolTip(folderPath);

    if(displayString.length()>150)
        displayString=displayString.mid(0,150)+"...";
    ui->currentFolderLabel->setText(""+displayString);

    ui->currentFileLabel->setToolTip(filename);
    ui->currentFileLabel->setText(filename);
}

}

void mainScreen::stopClamdInstance()
{
    clamd->close();
    scanningStarted=false;
}

void mainScreen::stopClamdscan()
{
    if(!clamdscan->isOpen())
        return;

    disconnect(timer,SIGNAL(timeout()),this,SLOT(updateElapsedTime()));
    timer->stop();

    quint64 time=elapsedTimer.elapsed()/1000;
    ui->timeElapsedLabel->setText("<b>"+QDateTime::fromTime_t(time).toUTC().toString("hh %1 mm %2 ss %3").arg("hrs","mins","secs")+"</b>");

    ui->scanningStatus->setText("<b>Completed<b>");
    ui->scanningProgressbar->setValue(ui->scanningProgressbar->maximum());
    clamdscan->close();
    scanningStarted=false;

    ui->stopScanButton->setEnabled(false);
    ui->backButton->setEnabled(true);

    continueCustomScan();
}

void mainScreen::updateElapsedTime()
{
    quint64 time=elapsedTimer.elapsed()/1000;

    ui->timeElapsedLabel->setText(QDateTime::fromTime_t(time).toUTC().toString("hh %1 mm %2 ss %3").arg("hrs","mins","secs"));
}

void mainScreen::setDefaultActionText()
{
    QString text="No Action Taken";

    if(defaultAction=="copy")
        text="Copy Infected Files To Quarantine";
    else if(defaultAction=="move")
        text="Move Infected Files To Quarantine";
    else if(defaultAction=="delete")
        text="Delete Infected Files";

    ui->actionTakenLabel->setText(text);
    ui->scanningStatus->setText("Scanning");
    showTrayMessage(applicationName,"Scanning Started");

    ui->stopScanButton->setEnabled(true);
    ui->backButton->setEnabled(false);
}

void mainScreen::clamdscanStarted()
{
    qDebug()<<"clamdscan started with arguments..Waiting for output"<<clamdscan->program()<<clamdscan->arguments();

    ui->threatsDetectedLabel->setText("0");

    threats=0;
    elapsedTimer.start();

    timer->start(1000);

    scanningStarted=true;
    ui->scanningProgressbar->setValue(0);
    ui->scanningTab->setTitle(scanTitle);
}


void mainScreen::on_statusButton_toggled(bool checked)
{
    if(scanningStarted)
    {
        if(!checked)
    {
        ui->statusButton->setChecked(true);
        QMessageBox::warning(this,"Scanning Active","Your System is being Scanned for Threats");
        return;
    }
    }
    else{
    ui->stackedDisplay->setCurrentIndex(0);
    ui->statusDisplay->setCurrentIndex(0);
    }
}


void mainScreen::on_speedUpButton_toggled(bool checked)
{
    if(!checked)
        return;
    if(scanningStarted)
    {
        QMessageBox::warning(this,"Scanning Active","Your System is being Scanned for Threats");
        return;
    }
    ui->stackedDisplay->setCurrentIndex(1);
}


void mainScreen::on_optimizerButton_toggled(bool checked)
{
    if(!checked)
        return;
    if(scanningStarted)
    {
        QMessageBox::warning(this,"Scanning Active","Your System is being Scanned for Threats");
        return;
    }
    ui->stackedDisplay->setCurrentIndex(2);
}


void mainScreen::on_settingsButton_toggled(bool checked)
{
    if(!checked){
        writeDatabaseConfiguration();
        return;
    }
    if(scanningStarted)
    {
        QMessageBox::warning(this,"Scanning Active","Your System is being Scanned for Threats");
        return;
    }
    ui->stackedDisplay->setCurrentIndex(3);
}


void mainScreen::closeEvent(QCloseEvent *event)
{
    hide();
    showTrayMessage(applicationName,secureStatusString);
    event->ignore();
}

void mainScreen::changeEvent(QEvent *event)
{
    if(event->type()==QEvent::WindowStateChange){
        if(isMinimized())
        {
            //hide();
//        showTrayMessage(applicationName,"Application Minimized To Tray");
    }
    }

}


void mainScreen::on_stopScanButton_clicked()
{
    if(!clamdscan->isOpen())
        return;

    disconnect(timer,SIGNAL(timeout()),this,SLOT(updateElapsedTime()));
    timer->stop();

    quint64 time=elapsedTimer.elapsed()/1000;
    ui->timeElapsedLabel->setText("<b>"+QDateTime::fromTime_t(time).toUTC().toString("hh %1 mm %2 ss %3").arg("hrs","mins","secs")+"</b>");

    ui->scanningStatus->setText("<b>Completed<b>");
    ui->scanningProgressbar->setValue(ui->scanningProgressbar->maximum());
    clamdscan->close();
    scanningStarted=false;
    customFinished=true;

    disconnect(clamdscan,SIGNAL(started()),this,SLOT(clamdscanStarted()));
    disconnect(clamdscan,SIGNAL(errorOccurred(QProcess::ProcessError)),this,SLOT(handleClamdscanProcessError(QProcess::ProcessError)));
    disconnect(clamdscan,SIGNAL(readyReadStandardOutput()),this,SLOT(readClamdscanOutput()));

    ui->stopScanButton->setEnabled(false);
    ui->backButton->setEnabled(true);
}


void mainScreen::on_fullVirusScan_clicked()
{
    scanTitle="Performing Full System Scan";
    QFileDialog dialog;
    QString dirPath="C:\\";//dialog.getExistingDirectory(this,"Select Drive",QString("C:\\")).replace("/","\\");

    if(dirPath.isEmpty())
        return;

    QStringList arguments=buildArguments(1,dirPath);
    qDebug()<<arguments;

    filesCounter->setCustomScanFlag(false);
    countFiles(dirPath);

    customFinished=true;

    filesScanned=0;
    threats=0;

    startClamdscan(arguments);
}


void mainScreen::on_selectDirectoryButton_clicked()
{
    QFileDialog dialog;
    QString dirPath=dialog.getExistingDirectory(this,"Select Custom Drive",QString()).replace("/","\\");

    if(dirPath.isEmpty())
        return;

    scanItemsList.append(dirPath);
    scanItemsListModel.setStringList(scanItemsList);
}

void mainScreen::on_selectFilesButtonn_clicked()
{
    QFileDialog dialog;
    QStringList filesPath=dialog.getOpenFileNames(this,"Select Files To Scan");

    if(filesPath.isEmpty())
        return;

    scanItemsList.append(filesPath.join("#").replace("/","\\").split("#"));
    scanItemsListModel.setStringList(scanItemsList);
}


void mainScreen::on_customScan_clicked()
{
    scanItemsList.clear();
    scanItemsListModel.setStringList(scanItemsList);
    ui->statusDisplay->setCurrentIndex(1);
}


void mainScreen::on_startCustomScanButton_clicked()
{
    if(scanItemsList.isEmpty())
    {
        customFinished=true;
        return;
    }

    scanTitle="Starting Scan";

    if(customFinished)
    {
        filesScanned=0;
        threats=0;
        filesCounter->setCustomScanFlag(true);
        filesCounter->setCustomScanList(scanItemsList);
        countFiles("");
    }

    QString path=scanItemsList.takeFirst();

    QStringList arguments=buildArguments(1,path);
    qDebug()<<arguments;

    customFinished=false;
    startClamdscan(arguments);
}

void mainScreen::addScanItemsToFile()
{
    QFile scanItemsFile(scanItemsFileName);
        scanItemsFile.open(QIODevice::WriteOnly | QIODevice::Text);
        scanItemsFile.write(scanItemsList.join("\n").toUtf8());
        scanItemsFile.waitForBytesWritten(1000);
        scanItemsFile.close();
}


void mainScreen::on_targetedScan_clicked()
{
    scanTitle="Scanning Selected Drive";
    QFileDialog dialog;

    QString dirPath=dialog.getExistingDirectory(this,"Select Target Drive",QString("C:\\")).replace("/","\\");

    if(dirPath.isEmpty())
        return;

    QStringList arguments=buildArguments(1,dirPath);
    qDebug()<<arguments;

    filesCounter->setCustomScanFlag(false);
    countFiles(dirPath);

    customFinished=true;

    filesScanned=0;
    threats=0;

    startClamdscan(arguments);
}

void mainScreen::continueCustomScan()
{
    if(!customFinished)
    on_startCustomScanButton_clicked();
}

void mainScreen::countFiles(QString path)
{
    filesCounter->terminate();
    filesCounter->wait(5000);
    filesCounter->setDirPath(path);
    filesCounter->start();
}

void mainScreen::filesCounterStarted()
{
qDebug()<<"Started Counting Files";

}

void mainScreen::on_performQuickScanButton_clicked()
{
    QDir systemDrive("C:\\");

    QStringList normalFiles=systemDrive.entryList(QDir::AllDirs | QDir::NoDotAndDotDot);
    QStringList systemFiles=systemDrive.entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::System |QDir::Hidden);

    foreach(QString item, normalFiles)
        systemFiles.removeOne(item);

    systemFiles.removeOne("ProgramData");

    foreach(QString item, systemFiles)
        scanItemsList.append(systemDrive.path().replace("/","\\")+item);

    quickscan=true;
    on_startCustomScanButton_clicked();

}

void mainScreen::showEngineInformation()
{
    ui->logViewer->clear();
    connect(freshclam,SIGNAL(readyReadStandardOutput()),this,SLOT(showFreshClamOutput()),Qt::UniqueConnection);
    freshclam->start("freshclam.exe");
}

void mainScreen::showFreshClamOutput()
{
    QStringList temp=QString(freshclam->readAll()).split('\n',QString::SkipEmptyParts);
    if(temp.isEmpty())
        return;

    QString output=temp.last().simplified();
    qDebug()<<output;

    ui->logViewer->setText(temp.join("\n"));
    showStatusMessage(output);
}

void mainScreen::showClamdOutputAsStatus()
{
    QStringList temp=QString(clamd->readAllStandardError()).split('\n',QString::SkipEmptyParts);
    if(temp.isEmpty())
        return;

    QString output=temp.last().simplified();
    qDebug()<<output;

    showStatusMessage(output);
}


void mainScreen::showStatusMessage(QString message)
{
    databaseLabel->setText(message);
    databaseLabel->setToolTip(message);
}

void mainScreen::on_showLogs_clicked()
{
    QFile logFile(QDir(qApp->applicationDirPath()).absoluteFilePath(" "+logFileName));
    logFile.open(QIODevice::ReadOnly);

    QString logs=QString(logFile.readAll()).replace("FOUND","<font color=red> FOUND </font>").replace("\n","<br>");

    ui->logViewer->setHtml(logs);
}


void mainScreen::on_moveToQuarantine_toggled(bool checked)
{
    if(checked)
        defaultAction="move";
}


void mainScreen::on_copyToQuarantine_toggled(bool checked)
{
    if(checked)
        defaultAction="copy";
}


void mainScreen::on_deleteVirus_toggled(bool checked)
{
    if(checked)
        defaultAction="delete";
}

void mainScreen::on_backButton_clicked()
{
    ui->stackedDisplay->setCurrentIndex(0);
    ui->statusDisplay->setCurrentIndex(0);
}

void mainScreen::showTrayMessage(QString title, QString message,int msecs)
{
    if(isHidden() && !silent)
        trayIcon->showMessage(title,message,QIcon(":/avaxi.png"),msecs);
}

void mainScreen::setTrayIcon()
{

    trayIcon = new QSystemTrayIcon(QIcon(":/avaxi.png"),this);
    trayMenu = new QMenu(this);


    trayIcon->setContextMenu(trayMenu);
    trayIcon->setToolTip(secureStatusString+"\n"+applicationName+"\n"+QDateTime::currentDateTime().toString("MMMM dd, yyyy"));

    actionOpenAntivirus = new QAction("Open Antivirus",this);
    connect(actionOpenAntivirus,SIGNAL(triggered()),this,SLOT(showNormal()),Qt::UniqueConnection);
    trayMenu->addAction(actionOpenAntivirus);

    actionQuickScan = new QAction("Quick Scan",this);
    connect(actionQuickScan,SIGNAL(triggered()),this,SLOT(doQuickScan()),Qt::UniqueConnection);
    trayMenu->addAction(actionQuickScan);

    actionUpdateDatabase = new QAction("Update Database",this);
    connect(actionUpdateDatabase,SIGNAL(triggered()),this,SLOT(updateVirusDatabase()),Qt::UniqueConnection);
    trayMenu->addAction(actionUpdateDatabase);

    actionEnableSilentMode = new QAction("Enable Silent Mode",this);
    connect(actionEnableSilentMode,SIGNAL(triggered()),this,SLOT(enableSilentMode()),Qt::UniqueConnection);
    trayMenu->addAction(actionEnableSilentMode);

    actionCloseAntivirus = new QAction("Close Antivirus",this);
    connect(actionCloseAntivirus,SIGNAL(triggered()),this,SLOT(exitNicely()),Qt::UniqueConnection);
    trayMenu->addAction(actionCloseAntivirus);


    trayIcon->show();
}

void mainScreen::doQuickScan()
{
 showNormal();
 on_performQuickScanButton_clicked();
}

void mainScreen::updateVirusDatabase()
{
    showNormal();
    showEngineInformation();
}

void mainScreen::enableSilentMode()
{
    if(!silent){
    QString text="Silent Mode will temporarily stop displaying alert messages and other general notifications.\n\nIt is useful while "
"working with full screen applications like important video meetings and games.\n";
    text+=applicationName+" will continue protecting your computer in the background against threats.\nEnable Silent Mode?";

    QMessageBox::StandardButton choice;
    choice=QMessageBox::question(this,applicationName,text,QMessageBox::Yes|QMessageBox::No);

    if(choice==QMessageBox::Yes){
        silent=true;
    actionEnableSilentMode->setText("Disable Silent Mode");
    }
    }
    else
    {
        silent=false;
        actionEnableSilentMode->setText("Enable Silent Mode");
    }
}

void mainScreen::exitNicely()
{
    showTrayMessage(applicationName,"Virus Protection Has Been Turned Off");
    trayIcon->hide();

    stopClamdInstance();
    stopClamdscan();
    killClamd();
    clamscan->close();
    freshclam->close();
    trayIcon->hide();
    QApplication::quit();
}

//Qt Information, Virtual Keyboard.

void mainScreen::on_scanForJunk_clicked()
{
    tempFilesPath.setStringList(QStringList());
    connect(tempCleaner,SIGNAL(foundPath(QString)),this,SLOT(foundPath(QString)),Qt::UniqueConnection);
    tempCleaner->setScanMode(true);
    tempCleaner->start();
}

void mainScreen::on_optimize_clicked()
{
    connect(tempCleaner,SIGNAL(deletedPath(QString,QString)),this,SLOT(deletedPath(QString,QString)),Qt::UniqueConnection);
    tempCleaner->setScanMode(false);
    tempCleaner->start();
}

void mainScreen::on_stayOnTop_toggled(bool checked)
{
    setWindowFlag(Qt::WindowStaysOnTopHint,checked);
    show();
}

void mainScreen::foundPath(QString path)
{
    QStringList list=tempFilesPath.stringList();
    list.append(path);
    tempFilesPath.setStringList(list);
    ui->optimizeProgressBar->setMaximum(list.size());
    ui->optimizeProgressBar->setFormat(tr("Found %1").arg(path.split("\\").last()));
}

void mainScreen::deletedPath(QString path,QString total)
{
    QStringList list=tempFilesPath.stringList();
    list.removeOne(path);
    tempFilesPath.setStringList(list);
    qDebug()<<ui->optimizeProgressBar->maximum()<<list.size();
    ui->optimizeProgressBar->setValue(ui->optimizeProgressBar->maximum()-list.size());
    ui->optimizeProgressBar->setFormat(tr("Deleting %1").arg(path.split("\\").last()));
    ui->junkFilesLabel->setText(QString(list.length()));
    ui->junkSizeLabel->setText(total);

}

void mainScreen::on_minimizeButton_clicked()
{
    setWindowState(Qt::WindowMinimized);
}


void mainScreen::on_closeButton_clicked()
{
    close();
}

void mainScreen::on_optimizeProgressBar_valueChanged(int value)
{
    if(value<ui->optimizeProgressBar->maximum()/2)
        ui->optimizeProgressBar->setStyleSheet(danger);
    else
        ui->optimizeProgressBar->setStyleSheet("color:black");
}


void mainScreen::on_excludeFiles_textChanged(const QString &arg1)
{
    excludeFilesRegex.clear();
    QStringList temp=arg1.split(',',QString::SkipEmptyParts);
    foreach(QString path,temp)
     {   if(path.contains("\\"))
        excludeFilesRegex+=tr("\nExcludePath \"%1\"").arg(path);
        else
            excludeFilesRegex+=tr("\nExcludePath \"%1\"").arg(QDir(qApp->applicationDirPath()).absoluteFilePath(path).replace("/","\\"));
    }

        qDebug()<<excludeFilesRegex;
}


void mainScreen::on_silentMode_toggled(bool checked)
{
        enableSilentMode();
        if(silent)
            ui->silentMode->setChecked(true);
        else
            ui->silentMode->setChecked(false);
}


void mainScreen::on_excludefiles_textChanged()
{
    on_excludeFiles_textChanged(ui->excludefiles->toPlainText());
}

void mainScreen::deleteWindowsExplorerHistory()
{
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",QSettings::NativeFormat);
    qDebug()<<settings.childKeys();
    QStringList temp=speedupModel.stringList();
    if(speedupSearch){
    temp.append(settings.childGroups());
    speedupModel.setStringList(temp);
    }
    else
    {
        ui->progressWinSearchHist->setValue(qrand()%60+20);
        settings.remove("");
    temp.append("Deleted Windows Explorer Search History");
    speedupModel.setStringList(temp);
    QThread::msleep(100);
    ui->progressWinSearchHist->setValue(100);
    }
}

void mainScreen::clearSystemClipboard()
{
    if(speedupSearch)
        return;

    QThread::msleep(100);
    qApp->clipboard()->setText(QString());
    ui->progressClipboard->setValue(qrand()%60+20);
    QThread::msleep(100);
    ui->progressClipboard->setValue(100);

    QStringList temp=speedupModel.stringList();
    temp.append("Clipboard Memory Cleared Successfully");
    speedupModel.setStringList(temp);
}

void mainScreen::deleteRecentDocuments()
{
    QString documents=QStandardPaths::locate(QStandardPaths::DocumentsLocation,QString(),QStandardPaths::LocateDirectory);
    QDir documentsDir(documents);
    documentsDir.setFilter(QDir::NoDotAndDotDot|QDir::AllEntries);
    QStringList temp=speedupModel.stringList();
    if(speedupSearch){
    temp.append(documentsDir.entryList());
    speedupModel.setStringList(temp);
    qDebug()<<documentsDir.entryList();
    }
    else
    {
    QThread::msleep(300);
    documentsDir.removeRecursively();
    temp.append("Deleted all Recent Documents");
    speedupModel.setStringList(temp);
    ui->progressRecentDocuments->setValue(qrand()%60+20);
    QThread::msleep(300);
    ui->progressRecentDocuments->setValue(100);
    }
}

void mainScreen::deleteStartupFiles()
{
    QString home=QStandardPaths::locate(QStandardPaths::HomeLocation,QString(),QStandardPaths::LocateDirectory).replace("/","\\");
    QString startup=home+"\\"+QString("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    qDebug()<<startup;

    QDir startupDir(startup);
    startupDir.setFilter(QDir::NoDotAndDotDot|QDir::AllEntries);
    QStringList temp=speedupModel.stringList();
    if(speedupSearch){
    temp.append(startupDir.entryList());
    speedupModel.setStringList(temp);
    qDebug()<<startupDir.entryList();
    }
    else{
    QThread::msleep(300);
    startupDir.removeRecursively();
    temp.append("Deleted all Startup Files");
    speedupModel.setStringList(temp);
    ui->progressStartupFiles->setValue(qrand()%70+20);
    QThread::msleep(200);
    ui->progressStartupFiles->setValue(100);
}
}

void mainScreen::removeUnusedFileExtensions()
{
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts",QSettings::NativeFormat);
    qDebug()<<settings.childGroups();

    QStringList temp=speedupModel.stringList();
    if(speedupSearch){
    temp.append(settings.childGroups());
    speedupModel.setStringList(temp);
    }
    else
    {
    ui->progressUnusedFilesExt->setValue(qrand()%60+20);
        settings.remove("");
    temp.append("Deleted unused file extensions");
    speedupModel.setStringList(temp);
    QThread::msleep(100);
    ui->progressUnusedFilesExt->setValue(100);
    }
}


void mainScreen::on_speedUpSearch_clicked()
{
    speedupModel.setStringList(QStringList());
    speedupSearch=true;
    ui->progressWinSearchHist->reset();
    ui->progressClipboard->reset();
    ui->progressRecentDocuments->reset();
    ui->progressStartupFiles->reset();
    ui->progressUnusedFilesExt->reset();

    if(ui->winExplorerSearchHistory->isChecked())
    deleteWindowsExplorerHistory();
    if(ui->clipboard->isChecked())
    clearSystemClipboard();
    if(ui->recentDocuments->isChecked())
    deleteRecentDocuments();
    if(ui->startupFiles->isChecked())
    deleteStartupFiles();
    if(ui->unusedFileExtensions->isChecked())
    removeUnusedFileExtensions();
}

void mainScreen::on_speedUpBoost_clicked()
{
    speedupModel.setStringList(QStringList());
    speedupSearch=false;
    if(ui->winExplorerSearchHistory->isChecked())
    deleteWindowsExplorerHistory();
    if(ui->clipboard->isChecked())
    clearSystemClipboard();
    if(ui->recentDocuments->isChecked())
    deleteRecentDocuments();
    if(ui->startupFiles->isChecked())
    deleteStartupFiles();
    if(ui->unusedFileExtensions->isChecked())
    removeUnusedFileExtensions();
}



void mainScreen::on_about_clicked()
{
    QMessageBox::aboutQt(this,applicationName+" "+qApp->applicationVersion());
}

