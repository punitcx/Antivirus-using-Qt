#ifndef STARTUPANIMATION_H
#define STARTUPANIMATION_H

#include <QObject>
//#include<QDesktopWidget>
#include<QSequentialAnimationGroup>
#include<QPropertyAnimation>
#include<QLabel>
#include<QApplication>
#include<QProgressBar>
#include<QDebug>
#include<QDialog>
#include<QScreen>
#include<QIcon>
#include<QVBoxLayout>

class startupAnimation : public QDialog
{
    Q_OBJECT
    QThread *t;
protected:
    QLabel *mainLabel,*innerLabel;
public:
    startupAnimation();
public slots:
    void showAnimation();
    void hideLabel();
};

#endif // STARTUPANIMATION_H
