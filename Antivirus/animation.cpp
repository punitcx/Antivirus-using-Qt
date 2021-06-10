#include "animation.h"
void startupAnimation::hideLabel()
{
    mainLabel->hide();
}

startupAnimation::startupAnimation()
{
this->setWindowOpacity(0);

}

void startupAnimation::showAnimation()
{
    mainLabel=new QLabel;

    innerLabel=new QLabel;
    QVBoxLayout layout(mainLabel);
    mainLabel->setLayout(&layout);

    QProgressBar *loader=new QProgressBar(mainLabel);

    loader->setFormat("Starting Antivirus Engine...");
    loader->setAlignment(Qt::AlignHCenter);
    //qDebug()<<
    loader->size().height();

    QPixmap startup(":/avaxilogo.png");
    QScreen *desktop=QApplication::primaryScreen();
    mainLabel->setWindowFlags(Qt::FramelessWindowHint|Qt::Dialog|Qt::WindowTitleHint);
    mainLabel->setWindowFlag(Qt::WindowStaysOnTopHint,true);
    mainLabel->setWindowIcon(QIcon(":/avaxi.png"));

    layout.setContentsMargins(1,1,1,1);
    mainLabel->setWindowOpacity(0.95);
    innerLabel->setPixmap(startup);
    innerLabel->setScaledContents(true);

    int dw=desktop->size().width();
    int dh=desktop->size().height();
    int aw=startup.width();
    int ah=startup.height();

    layout.addWidget(loader);
    layout.addWidget(innerLabel);
    loader->setGeometry(0,0,aw,30);

    QSequentialAnimationGroup *group=new QSequentialAnimationGroup;
    //qDebug()<<dw<<dh<<aw<<ah<<startup.width()<<startup.height();
       QPropertyAnimation *animation=new QPropertyAnimation(mainLabel,"geometry");
       QPropertyAnimation *progressAnimation=new QPropertyAnimation(loader,"value");

       progressAnimation->setStartValue(0);
       progressAnimation->setEndValue(100);
       progressAnimation->setDuration(20000);//20000

       animation->setStartValue(QRect(QPoint(100,100),QSize(aw/5,ah/5)));
       //animation->setKeyValueAt(0.1,QRect(QPoint(100,100),QSize(aw/5,ah/5)));
       animation->setEndValue(QRect(QPoint((dw-aw)/2,(dh-ah)/2),QSize(aw,ah)));

       animation->setDuration(2000);

       group->addAnimation(animation);
       group->addAnimation(progressAnimation);

       mainLabel->show();

       connect(group,SIGNAL(finished()),this,SLOT(close()));
       group->start();
       exec();
}

