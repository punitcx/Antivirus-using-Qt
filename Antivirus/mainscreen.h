#ifndef MAINSCREEN_H
#define MAINSCREEN_H

#include <QDebug>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QClipboard>
#include <QMainWindow>
#include <QFile>
#include <QFileDialog>
#include <QInputDialog>
#include <QCloseEvent>
#include <QStringListModel>
#include <QTime>
#include <QTimer>
#include <QElapsedTimer>
#include <clamdprocess.h>
#include <clamdscanprocess.h>
#include <clamscanprocess.h>
#include <freshclamprocess.h>
#include <cleaner.h>
#include <customthread.h>
#include "animation.h"
#include <QSettings>
#include <QStandardPaths>
#include <QMediaPlayer>

QT_BEGIN_NAMESPACE
namespace Ui { class mainScreen; }
QT_END_NAMESPACE

class mainScreen : public QMainWindow
{
    Q_OBJECT

public:
    mainScreen(QWidget *parent = nullptr);
    ~mainScreen();

private:
    void allocateObjects();
    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
    void closeEvent(QCloseEvent *event);
    int m_nMouseClick_X_Coordinate;
    int m_nMouseClick_Y_Coordinate;
    int flag=0;
    void changeEvent(QEvent *event);
private slots:

    void doStartupAnimation();

    void adjustLayouts();

    void setTrayIcon();

    void countFiles(QString path);

    void filesCounterStarted();

    void doInitialization();

    QStringList buildArguments(QString fromFile, QString wait, QString log, QString action, QString multiscan);

    QStringList buildArguments(bool notCustom,QString dirName, QString wait, QString log, QString action);

    void writeDatabaseConfiguration();

    void startClamdInstance();

    void clamdStarted();

    void handleClamdProcessError(QProcess::ProcessError error);

    void readClamdOutput();

    void stopClamdInstance();

    void startClamdscan(QStringList arguments);

    void handleClamdscanProcessError(QProcess::ProcessError error);

    void readClamdscanOutput();

    void clamdscanStarted();

    void stopClamdscan();

    void updateElapsedTime();

    void setDefaultActionText();

    void on_statusButton_toggled(bool checked);

    void on_speedUpButton_toggled(bool checked);

    void on_optimizerButton_toggled(bool checked);

    void on_settingsButton_toggled(bool checked);

    void on_stopScanButton_clicked();

    void on_fullVirusScan_clicked();

    void on_selectDirectoryButton_clicked();

    void on_selectFilesButtonn_clicked();

    void on_customScan_clicked();

    void on_startCustomScanButton_clicked();

    void addScanItemsToFile();

    void on_targetedScan_clicked();

    void continueCustomScan();

    void killClamd();

    void on_performQuickScanButton_clicked();

    void showEngineInformation();

    void showFreshClamOutput();

    void showClamdOutputAsStatus();

    void showStatusMessage(QString message);

    void on_showLogs_clicked();

    void on_moveToQuarantine_toggled(bool checked);

    void on_copyToQuarantine_toggled(bool checked);

    void on_deleteVirus_toggled(bool checked);

    void on_backButton_clicked();

    void showTrayMessage(QString title, QString message, int msecs=4000);

    void doQuickScan();

    void updateVirusDatabase();

    void enableSilentMode();

    void exitNicely();

    void on_scanForJunk_clicked();

    void on_stayOnTop_toggled(bool checked);

    void foundPath(QString path);

    void deletedPath(QString path, QString total);

    void on_optimize_clicked();

    void on_minimizeButton_clicked();

    void on_closeButton_clicked();

    void on_optimizeProgressBar_valueChanged(int value);

    void on_excludeFiles_textChanged(const QString &arg1);

    void on_silentMode_toggled(bool checked);

    void on_excludefiles_textChanged();

private slots:
    void deleteWindowsExplorerHistory();
    void clearSystemClipboard();
    void deleteRecentDocuments();
    void deleteStartupFiles();
    void removeUnusedFileExtensions();
    void on_speedUpBoost_clicked();
    void on_speedUpSearch_clicked();


    void on_about_clicked();

private:
    Ui::mainScreen *ui;

    startupAnimation *animation;

    QMediaPlayer *player;

    QLabel *databaseLabel;
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;
    QAction *actionOpenAntivirus,*actionCloseAntivirus,*actionQuickScan,*actionUpdateDatabase,*actionEnableSilentMode;


    customThread *filesCounter;
    clamdProcess *clamd;
    clamdscanProcess *clamdscan;
    clamscanProcess *clamscan;
    freshclamProcess *freshclam;
    cleaner *tempCleaner;

    QElapsedTimer elapsedTimer;
    QTimer *timer,*databaseUpdateTimer;

    int filesScanned=0,threats=0;
    bool silent=false;
    bool customFinished=true;
    bool quickscan=false;
    bool scanningStarted=false;
    bool speedupSearch=true;

    QString danger = "QProgressBar::chunk {background: QLinearGradient( x1: 0, y1: 0, x2: 1, y2: 0,stop: 0 #FF0350,stop: 0.4999 #FF0020,stop: 0.5 #FF0019,stop: 1 #FF0000 );border-bottom-right-radius: 5px;border-bottom-left-radius: 5px;border: .px solid black;}";


    QString scanItemsFileName="files.txt",logFileName="scanlog.txt";
    QString quarantineDir="C:\\quarantine";

    QString defaultAction="copy";
    QString includeFilesRegex="";
    QString includeDirsRegex="";
    QString excludeFilesRegex="";

    QStringListModel scanItemsListModel;
    QStringListModel tempFilesPath;
    QStringList scanItemsList;
    QStringListModel speedupModel;
    QString scanTitle="Scanning";
    QString applicationName="Avaxi Antivirus";
    QString secureStatusString="Your System Is Secure";

};
#endif // MAINSCREEN_H
