#include "injectionwindow.h"
#include "./ui_injectionwindow.h"

#include "stringsearch.h"

#include <QtCore>
#include <QtGui>
#include <QMessageBox>
#include <QFileDialog>

#include "magic_enum.hpp"

void register_injection_modes(Ui::InjectionWindow* ui, InjectionMethod& default_method);

InjectionWindow::InjectionWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::InjectionWindow)
{
    ui->setupUi(this);
    setWindowTitle("Injector");
    pull_processes();
    list_all_processes();

    // ================ Slots and Signals ================
    ui->listWidgetProcesses->connect(ui->listWidgetProcesses, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(process_list_item_clicked(QListWidgetItem*)));
    ui->lineEditProcessSearch->connect(ui->lineEditProcessSearch, SIGNAL(textChanged(const QString&)), this, SLOT(process_search_text_changed(const QString&)));
    ui->comboBoxInjectionModes->connect(ui->comboBoxInjectionModes, SIGNAL(currentIndexChanged(int)), this, SLOT(injection_method_index_changed(int)));
    ui->pushButtonBrowse->connect(ui->pushButtonBrowse, SIGNAL(clicked(bool)), this, SLOT(browse_dll_path_click(bool)));
    ui->pushButtonInject->connect(ui->pushButtonInject, SIGNAL(clicked(bool)), this, SLOT(inject_click(bool)));

    register_injection_modes(ui, this->injection_method);
}

void register_injection_modes(Ui::InjectionWindow* ui, InjectionMethod& default_method)
{
    auto values = magic_enum::enum_values<InjectionMethod>();
    for(const auto& var : values)
    {
        ui->comboBoxInjectionModes->addItem(static_cast<std::string>(magic_enum::enum_name(var)).c_str());
    }
    int index_of_default = ui->comboBoxInjectionModes->findText(static_cast<std::string>(magic_enum::enum_name(default_method)).c_str());
    ui->comboBoxInjectionModes->setCurrentIndex(index_of_default);
}

InjectionWindow::~InjectionWindow()
{
    delete ui;
}

// ================ Listener ================

void InjectionWindow::browse_dll_path_click(bool checked)
{
    QString path = QFileDialog::getOpenFileName(this, "Select a file.", "selection", "*.dll");
    this->pDllPath = path.toStdString();
    ui->lineEditDLLPath->setText(path);
}

void InjectionWindow::inject_click(bool checked)
{
    InjectionResult result;
    Injector*       injector;

    if(strlen(this->pDllPath.c_str()) == 0)
    {
        MessageBoxA(0, "Please select a DLL before injecting.", NULL, 0);
        return;
    }


    if(this->dwSelectedProcId == -1)
    {
        MessageBoxA(0, "No target process selected! Please enter a valid process id.", NULL, 0);
        return;
    }

    injector = get_by_type(this->injection_method);
    result = injector->inject(this->dwSelectedProcId, this->pDllPath.c_str());

    if(result.status == INJECTION_RESULT_ERROR)
    {
        MessageBoxA(0, result.error_msg, NULL, 0);
        return;
    }

    MessageBoxA(0, "Successfully injected into target process.", "Success", 0);
}

void InjectionWindow::process_search_text_changed(const QString &new_text)
{
    // Create a copy of the string to make the compiler shut the hell up
    std::string filter = new_text.toStdString();
    update_process_list_apply_filter(filter);
}

void InjectionWindow::process_list_item_clicked(QListWidgetItem* item)
{
    std::string text = item->text().toStdString();
    const char* find_begin = "[PID: ";
    char buf[MAX_PATH] {0};

    for(const PROCESSENTRY32W& pe32 : this->processes)
    {
        // very ugly solution but whatever, we don't give a fuck right here
        size_t index_pid = text.find(find_begin);

        if(index_pid > text.length() || index_pid < 0)
        {
            MessageBoxA(0, "There was an error parsing the pid of the selected process\nPlease enter it manually.", NULL, 0);
            return;
        }

        std::wcstombs(buf, pe32.szExeFile, MAX_PATH);
        std::string szExeName = text.substr(0, index_pid - 1);
        std::string pid_str = std::to_string(pe32.th32ProcessID);
        if(std::strcmp(buf, szExeName.c_str()) == 0 && text.find(pid_str) != std::string::npos)
        {
            this->dwSelectedProcId = pe32.th32ProcessID;
            ui->lineEditSelectedProcess->setText(pid_str.c_str());
        }
    }
}

void InjectionWindow::injection_method_index_changed(int index)
{
    if(index > magic_enum::enum_count<InjectionMethod>())
    {
        return;
    }

    auto values = magic_enum::enum_values<InjectionMethod>();
    for(const auto& var : values)
    {
        auto enum_index = magic_enum::enum_index<InjectionMethod>(var);
        if(index == enum_index)
        {
            this->injection_method = var;
        }
    }
}

// ================ Listener [End] ================



// ================ Definitions ================

void InjectionWindow::pull_processes()
{
    this->processes = Win::get_running_processes();
}

void InjectionWindow::list_all_processes()
{
    std::string empty_filter("");
    update_process_list_apply_filter(empty_filter);
}

void InjectionWindow::update_process_list()
{
    ui->listWidgetProcesses->clear();
    char buf[MAX_PATH] {0};
    for(PROCESSENTRY32& pe32 : this->processes)
    {
        StringSearch ss = StringSearch();
        std::wcstombs(buf, pe32.szExeFile, MAX_PATH);
        std::string proc_info = std::string(buf).append(" [PID: ").append(std::to_string(pe32.th32ProcessID)).append("]");
        const bool empty_filter = std::strcmp(this->process_list_filter.c_str(), "") == 0;
        if(empty_filter || ss.ci_find_substr(proc_info, (this->process_list_filter)) == 0)
        {
            ui->listWidgetProcesses->addItem(proc_info.c_str());
        }
    }
}

void InjectionWindow::update_process_list_apply_filter(std::string& new_filter)
{
    this->process_list_filter = new_filter;
    update_process_list();
}

// ================ Definitions [End] ================
