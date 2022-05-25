#ifndef INJECTIONWINDOW_H
#define INJECTIONWINDOW_H

#include <QMainWindow>
#include "qlistwidget.h"
#include "winutil.h"
#include "injector.h"

QT_BEGIN_NAMESPACE
namespace Ui { class InjectionWindow; }
QT_END_NAMESPACE

class InjectionWindow : public QMainWindow
{
    Q_OBJECT

public:
    InjectionWindow(QWidget *parent = nullptr);
    ~InjectionWindow();

    void list_all_processes();

    void update_process_list();

    void update_process_list_apply_filter(std::string& new_filter);

private slots:
    void browse_dll_path_click(bool checked);

    void refresh_process_list_click(bool checked);

    void inject_click(bool checked);

    void process_search_text_changed(const QString &arg1);

    void process_list_item_clicked(QListWidgetItem* item);

    void injection_method_index_changed(int index);

private:
    std::string process_list_filter;
    std::list<PROCESSENTRY32> processes;
    std::string pDllPath;

    DWORD dwSelectedProcId = -1;
    InjectionMethod injection_method = InjectionMethod::MANUAL_MAP;

    Ui::InjectionWindow *ui;

    void pull_processes();
};

#endif // INJECTIONWINDOW_H
