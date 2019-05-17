#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProcess>


#define CRYPTOPP_DEFAULT_NO_DLL
#include <cryptopp/dll.h>
#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif
#include <cryptopp/aes.h>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    static QString getCPUID();
private slots:
    void on_pbGenerate_clicked();

    void on_pbGenerateSn_clicked();

    void on_pbCpuidDt_clicked();

    void on_pbCreateRSAKeys_clicked();

    void on_pbVerify_clicked();

private:
    Ui::MainWindow *ui;
    string aesEnc(string plaintext);
    string aesDec(string ciphertext);
    string stdStringToHexString(string string);
    string hexStringToStdString(string string);
    void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);
    string RSADecryptString(const char *privFilename, const char *seed, const char *ciphertext);
    string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
    RandomPool &GlobalRNG();
};

#endif // MAINWINDOW_H
