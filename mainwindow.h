#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QTextEdit>
#include <QLineEdit>
#include <QProgressBar>
#include <QRadioButton>
#include <QButtonGroup>
#include <QNetworkAccessManager>
#include <QThread>

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#endif

enum ScanMode {
    FAST_AI_SCAN,
    DEEP_AI_AUDIT
};

class ScanWorker : public QObject {
    Q_OBJECT

public:
    ScanWorker(const QStringList &filesToScan, const QString &ghidraDir, const QString &apiKey, ScanMode mode);

public slots:
    void process();

signals:
    void logMessage(const QString &message);
    void threatFound(const QString &filePath, const QString &threatDetails);
    void finished();

private:
    QStringList m_files;
    QString m_ghidraDir;
    QString m_apiKey;
    ScanMode m_mode;

    // Fast AI Analysis (Raw Binary Features)
    bool fastAiScan(const QString &filePath, QString &outReason);

    // Deep Audit Pipeline Methods
    QJsonObject runDecompilePy(const QString &targetExe);
    bool screenWithHaiku(const QString &funcName, const QString &code);
    QString analyzeWithOpus(const QString &funcName, const QString &code);
    QString sendAnthropicApi(const QString &model, const QString &prompt, const QString &systemPrompt, int maxTokens);
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void selectFile();
    void selectFolder();
    void selectGhidraDir();
    void startScan();
    void handleThreat(const QString &filePath, const QString &threatDetails);
    void scanFinished();

private:
    QLineEdit *m_targetPathEdit;
    QLineEdit *m_ghidraPathEdit;
    QLineEdit *m_apiKeyEdit;
    QTextEdit *m_logEdit;
    QPushButton *m_scanBtn;
    QProgressBar *m_progressBar;

    QRadioButton *m_fastScanRadio;
    QRadioButton *m_deepScanRadio;

    QThread *m_workerThread;
    ScanWorker *m_worker;

    bool deleteFileWithElevation(const QString &filePath);
};

#endif // MAINWINDOW_H