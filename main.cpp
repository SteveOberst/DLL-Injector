#include "injectionwindow.h"

#include <QApplication>

const char* title = "Skidware Injector v0.1-alpha";


int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    InjectionWindow iw;
    iw.show();
    return app.exec();
}
