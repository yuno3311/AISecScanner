#include "mainwindow.h"
#include <QCoreApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QDirIterator>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QProcessEnvironment>
#include <QFileInfo>
#include <QDir>
#include <QFile>

// ---------------------------------------------------------
// ScanWorker Implementation
// ---------------------------------------------------------
ScanWorker::ScanWorker(const QStringList &filesToScan, const QString &ghidraDir, const QString &apiKey, ScanMode mode)
    : m_files(filesToScan), m_ghidraDir(ghidraDir), m_apiKey(apiKey), m_mode(mode) {}

void ScanWorker::process() {
    for (const QString &filePath : m_files) {
        emit logMessage(QString("\n=================================================="));
        emit logMessage(QString("[+] Processing Target: %1").arg(filePath));

        if (m_mode == FAST_AI_SCAN) {
            emit logMessage("[+] Mode: Fast AI Scan (Extracting raw binary vectors & static features)...");
            QString threatReason;
            if (fastAiScan(filePath, threatReason)) {
                emit logMessage(QString("  [!] MALICIOUS THREAT DETECTED: %1").arg(threatReason));
                emit threatFound(filePath, threatReason);
            } else {
                emit logMessage("  [✔] Fast AI Scan Cleared: Binary appears clean.");
            }
            continue;
        }

        // DEEP_AI_AUDIT Mode
        emit logMessage("[+] Mode: Deep AI Audit (Ghidra Extraction & Function Slicing)...");
        QJsonObject functions = runDecompilePy(filePath);

        if (functions.contains("error")) {
            emit logMessage(QString("[X] Decompile Error: %1").arg(functions["error"].toString()));
            continue;
        }

        emit logMessage(QString("[✔] Stage 2 Complete: %1 candidate functions extracted.").arg(functions.keys().size()));

        emit logMessage("[+] Stage 3: Screening with Claude 3.5 Haiku (The Sorter)...");
        QJsonObject flaggedFunctions;

        for (auto it = functions.constBegin(); it != functions.constEnd(); ++it) {
            QString funcName = it.key();
            QString code = it.value().toString();

            if (screenWithHaiku(funcName, code)) {
                emit logMessage(QString("  [!] FLAGGED SUSPICIOUS: %1").arg(funcName));
                flaggedFunctions.insert(funcName, code);
            } else {
                emit logMessage(QString("  [-] Cleared: %1").arg(funcName));
            }
        }

        if (flaggedFunctions.isEmpty()) {
            emit logMessage("[✔] Binary cleared: No suspicious functions detected.");
            continue;
        }

        emit logMessage(QString("[+] Stage 4 & 5: Running Deep Analysis with Claude 3 Opus on %1 function(s)...")
                            .arg(flaggedFunctions.size()));

        QString compiledReport;
        for (auto it = flaggedFunctions.constBegin(); it != flaggedFunctions.constEnd(); ++it) {
            QString funcName = it.key();
            QString code = it.value().toString();

            QString analysis = analyzeWithOpus(funcName, code);
            compiledReport += QString("### Function: `%1`\n%2\n\n").arg(funcName, analysis);
        }

        emit threatFound(filePath, compiledReport);
    }

    emit finished();
}

// Fast AI Scan: Feature Extraction without Decompilation
bool ScanWorker::fastAiScan(const QString &filePath, QString &outReason) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        outReason = "Unable to read binary file for static vector analysis.";
        return false;
    }

    // Extract headers, file size, and raw hexadecimal samples
    QByteArray headerSample = file.read(2048).toHex();
    qint64 fileSize = file.size();
    file.close();

    QString prompt = QString(
                         "You are an AI malware classifier performing real-time fast static feature analysis.\n"
                         "Target Path: %1\nFile Size: %2 bytes\nBinary Header (Hex Snippet): %3\n\n"
                         "Analyze the raw binary structure, PE headers, and byte sequence indicators for malware or malicious traits.\n"
                         "Respond strictly with 'MALICIOUS' or 'CLEAN' on the first line.\n"
                         "If MALICIOUS, output a concise explanation on the second line."
                         ).arg(filePath).arg(fileSize).arg(QString(headerSample));

    QString response = sendAnthropicApi("claude-haiku-4-5", prompt, "You are a fast AI binary malware detector.", 150);

    if (response.startsWith("MALICIOUS", Qt::CaseInsensitive) || response.contains("MALICIOUS")) {
        outReason = response.trimmed();
        return true;
    }

    return false;
}

QJsonObject ScanWorker::runDecompilePy(const QString &targetExe) {
    QProcess process;

    QString appDir = QCoreApplication::applicationDirPath();
    QString scriptPath = appDir + "/decompile.py";

    QString actualGhidraDir = m_ghidraDir;
    if (actualGhidraDir.isEmpty() || actualGhidraDir == "ghidra") {
        actualGhidraDir = appDir + "/ghidra";
    }

    scriptPath = QDir::toNativeSeparators(QFileInfo(scriptPath).absoluteFilePath());
    QString nativeTargetExe = QDir::toNativeSeparators(QFileInfo(targetExe).absoluteFilePath());
    QString nativeGhidraDir = QDir::toNativeSeparators(QFileInfo(actualGhidraDir).absoluteFilePath());

    if (!QFile::exists(scriptPath)) {
        QJsonObject errObj;
        errObj["error"] = QString("decompile.py not found at: %1").arg(scriptPath);
        return errObj;
    }

    process.setWorkingDirectory(QDir::toNativeSeparators(appDir));

    QString pythonExe = appDir + "/python.exe";
    if (!QFile::exists(pythonExe)) {
        pythonExe = "py";
    }
    pythonExe = QDir::toNativeSeparators(pythonExe);

#ifdef Q_OS_WIN
    QStringList args;
    args << "/c" << pythonExe << "-3" << "-u" << scriptPath << nativeTargetExe << nativeGhidraDir;
    process.setProgram("cmd.exe");
    process.setArguments(args);
#else
    process.setProgram("python3");
    process.setArguments(QStringList() << "-u" << scriptPath << nativeTargetExe << nativeGhidraDir);
#endif

    process.start();
    process.waitForFinished(-1);

    QByteArray stdOut = process.readAllStandardOutput();
    QByteArray stdErr = process.readAllStandardError();

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(stdOut, &parseError);

    if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
        return doc.object();
    }

    QJsonObject errObj;
    errObj["error"] = QString("Failed to parse JSON output.\n[Raw Stdout]: %1\n[Raw Stderr]: %2")
                          .arg(QString::fromUtf8(stdOut).trimmed())
                          .arg(QString::fromUtf8(stdErr).trimmed());
    return errObj;
}

QString ScanWorker::sendAnthropicApi(const QString &model, const QString &prompt, const QString &systemPrompt, int maxTokens) {
    QNetworkAccessManager netManager;
    QUrl url("https://api.anthropic.com/v1/messages");
    QNetworkRequest request(url);

    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("x-api-key", m_apiKey.toUtf8());
    request.setRawHeader("anthropic-version", "2023-06-01");

    QJsonObject jsonBody;
    jsonBody["model"] = model;
    jsonBody["max_tokens"] = maxTokens;
    jsonBody["temperature"] = 0.0;

    if (!systemPrompt.isEmpty()) {
        jsonBody["system"] = systemPrompt;
    }

    QJsonArray messages;
    QJsonObject msg;
    msg["role"] = "user";
    msg["content"] = prompt;
    messages.append(msg);
    jsonBody["messages"] = messages;

    QEventLoop loop;
    QNetworkReply *reply = netManager.post(request, QJsonDocument(jsonBody).toJson());
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    if (reply->error() != QNetworkReply::NoError) {
        reply->deleteLater();
        return "";
    }

    QByteArray responseData = reply->readAll();
    reply->deleteLater();

    QJsonObject root = QJsonDocument::fromJson(responseData).object();
    QJsonArray content = root["content"].toArray();

    if (!content.isEmpty()) {
        return content.first().toObject()["text"].toString();
    }
    return "";
}

bool ScanWorker::screenWithHaiku(const QString &funcName, const QString &code) {
    QString prompt = QString(
                         "Analyze this decompiled C function extracted from a binary:\n"
                         "Function: %1\n```c\n%2\n```\n\n"
                         "Is this function suspicious or worthy of deep security analysis?\n"
                         "Respond strictly with 'SUSPICIOUS' or 'SAFE' on the first line."
                         ).arg(funcName, code);

    QString result = sendAnthropicApi("claude-haiku-4-5", prompt, "", 100);
    return result.contains("SUSPICIOUS", Qt::CaseInsensitive);
}

QString ScanWorker::analyzeWithOpus(const QString &funcName, const QString &code) {
    QString systemPrompt = "You are an expert binary security auditor. Trace pointer logic, buffer boundaries, and logic errors. Provide specific vulnerability details and remediation strategies.";
    QString prompt = QString("Audit this function:\nFunction: %1\n```c\n%2\n```").arg(funcName, code);

    return sendAnthropicApi("clude-opus-5", prompt, systemPrompt, 1200);
}

// ---------------------------------------------------------
// MainWindow Implementation
// ---------------------------------------------------------
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("AI Binary Security Scanner & Auditor");
    resize(750, 600);

    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // API Key Row
    QHBoxLayout *apiLayout = new QHBoxLayout();
    m_apiKeyEdit = new QLineEdit(this);
    m_apiKeyEdit->setEchoMode(QLineEdit::Password);
    m_apiKeyEdit->setPlaceholderText("Enter Anthropic API Key...");
    QString envKey = QProcessEnvironment::systemEnvironment().value("ANTHROPIC_API_KEY");
    if (!envKey.isEmpty()) m_apiKeyEdit->setText(envKey);
    apiLayout->addWidget(m_apiKeyEdit);

    // Ghidra Path Row
    QHBoxLayout *ghidraLayout = new QHBoxLayout();
    m_ghidraPathEdit = new QLineEdit(this);
    m_ghidraPathEdit->setPlaceholderText("Ghidra Directory (Optional for Fast Mode)");
    QPushButton *btnGhidra = new QPushButton("Browse Ghidra", this);
    ghidraLayout->addWidget(m_ghidraPathEdit);
    ghidraLayout->addWidget(btnGhidra);

    // Scan Mode Selection
    QHBoxLayout *modeLayout = new QHBoxLayout();
    m_fastScanRadio = new QRadioButton("Fast AI Scan (No Decompilation - Instant Vector Analysis)", this);
    m_deepScanRadio = new QRadioButton("Deep AI Audit (Ghidra Decompilation + Haiku + Opus)", this);
    m_fastScanRadio->setChecked(true); // Default mode

    modeLayout->addWidget(m_fastScanRadio);
    modeLayout->addWidget(m_deepScanRadio);

    // Target Selection Row
    QHBoxLayout *pathLayout = new QHBoxLayout();
    m_targetPathEdit = new QLineEdit(this);
    m_targetPathEdit->setPlaceholderText("Select Executable (.exe) or Folder...");
    QPushButton *btnFile = new QPushButton("Browse File", this);
    QPushButton *btnFolder = new QPushButton("Browse Folder", this);
    pathLayout->addWidget(m_targetPathEdit);
    pathLayout->addWidget(btnFile);
    pathLayout->addWidget(btnFolder);

    // Layout Assembly
    mainLayout->addLayout(apiLayout);
    mainLayout->addLayout(ghidraLayout);
    mainLayout->addLayout(modeLayout);
    mainLayout->addLayout(pathLayout);

    m_scanBtn = new QPushButton("Start Security Scan", this);
    m_progressBar = new QProgressBar(this);
    m_progressBar->setRange(0, 0);
    m_progressBar->hide();

    mainLayout->addWidget(m_scanBtn);
    mainLayout->addWidget(m_progressBar);

    m_logEdit = new QTextEdit(this);
    m_logEdit->setReadOnly(true);
    mainLayout->addWidget(m_logEdit);

    setCentralWidget(centralWidget);

    connect(btnFile, &QPushButton::clicked, this, &MainWindow::selectFile);
    connect(btnFolder, &QPushButton::clicked, this, &MainWindow::selectFolder);
    connect(btnGhidra, &QPushButton::clicked, this, &MainWindow::selectGhidraDir);
    connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::startScan);
}

MainWindow::~MainWindow() {}

void MainWindow::selectFile() {
    QString file = QFileDialog::getOpenFileName(this, "Select Target Binary", "", "Executables (*.exe *.dll)");
    if (!file.isEmpty()) m_targetPathEdit->setText(file);
}

void MainWindow::selectFolder() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Target Folder");
    if (!dir.isEmpty()) m_targetPathEdit->setText(dir);
}

void MainWindow::selectGhidraDir() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Ghidra Installation Directory");
    if (!dir.isEmpty()) m_ghidraPathEdit->setText(dir);
}

void MainWindow::startScan() {
    QString target = m_targetPathEdit->text().trimmed();
    QString ghidraDir = m_ghidraPathEdit->text().trimmed();
    QString apiKey = m_apiKeyEdit->text().trimmed();

    if (target.isEmpty() || apiKey.isEmpty()) {
        QMessageBox::warning(this, "Missing Configuration", "Ensure Target File/Folder and API Key are set.");
        return;
    }

    ScanMode mode = m_fastScanRadio->isChecked() ? FAST_AI_SCAN : DEEP_AI_AUDIT;

    QStringList filesToScan;
    QFileInfo info(target);
    if (info.isFile()) {
        filesToScan.append(target);
    } else if (info.isDir()) {
        QDirIterator it(target, QStringList() << "*.exe" << "*.dll", QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext()) filesToScan.append(it.next());
    }

    m_scanBtn->setEnabled(false);
    m_progressBar->show();
    m_logEdit->clear();

    m_workerThread = new QThread(this);
    m_worker = new ScanWorker(filesToScan, ghidraDir, apiKey, mode);
    m_worker->moveToThread(m_workerThread);

    connect(m_workerThread, &QThread::started, m_worker, &ScanWorker::process);
    connect(m_worker, &ScanWorker::logMessage, m_logEdit, &QTextEdit::append);
    connect(m_worker, &ScanWorker::threatFound, this, &MainWindow::handleThreat);
    connect(m_worker, &ScanWorker::finished, m_workerThread, &QThread::quit);
    connect(m_worker, &ScanWorker::finished, m_worker, &QObject::deleteLater);
    connect(m_workerThread, &QThread::finished, m_workerThread, &QObject::deleteLater);
    connect(m_workerThread, &QThread::finished, this, &MainWindow::scanFinished);

    m_workerThread->start();
}

void MainWindow::handleThreat(const QString &filePath, const QString &threatDetails) {
    QMessageBox::StandardButton reply = QMessageBox::critical(
        this,
        "Vulnerabilities / Threats Identified!",
        QString("Threat findings for:\n%1\n\nDetails:\n%2\n\nWould you like to resolve/delete this threat now?")
            .arg(filePath, threatDetails.left(800) + "\n...[truncated]"),
        QMessageBox::Yes | QMessageBox::No
        );

    if (reply == QMessageBox::Yes) {
        QFile file(filePath);
        if (file.remove()) {
            m_logEdit->append(QString("[✔] File successfully removed: %1").arg(filePath));
        } else {
            m_logEdit->append("[!] Permission denied. Requesting Administrator privilege elevation...");
            if (deleteFileWithElevation(filePath)) {
                m_logEdit->append(QString("[✔] File deleted via Administrator elevation: %1").arg(filePath));
            } else {
                m_logEdit->append(QString("[X] Removal failed even with Administrator privileges: %1").arg(filePath));
            }
        }
    }
}

void MainWindow::scanFinished() {
    m_scanBtn->setEnabled(true);
    m_progressBar->hide();
    m_logEdit->append("\n[+] Security Scan Complete.");
    QMessageBox::information(this, "Finished", "Scanning operations finished.");
}

bool MainWindow::deleteFileWithElevation(const QString &filePath) {
#ifdef Q_OS_WIN
    QString nativePath = QDir::toNativeSeparators(filePath);
    QString params = QString("/c del /f /q \"%1\"").arg(nativePath);

    SHELLEXECUTEINFO shExInfo = {0};
    shExInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = (HWND)winId();
    shExInfo.lpVerb = L"runas";
    shExInfo.lpFile = L"cmd.exe";
    shExInfo.lpParameters = (LPCWSTR)params.utf16();
    shExInfo.nShow = SW_HIDE;

    if (ShellExecuteEx(&shExInfo)) {
        WaitForSingleObject(shExInfo.hProcess, INFINITE);
        CloseHandle(shExInfo.hProcess);
        return !QFile::exists(filePath);
    }
#endif
    return false;
}