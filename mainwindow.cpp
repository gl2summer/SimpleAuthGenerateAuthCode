#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QMessageBox>
#include <QTime>

byte aes_key[ CryptoPP::AES::DEFAULT_KEYLENGTH +1] = "v3guWjHnXCOmZkw=";
byte aes_iv[ CryptoPP::AES::BLOCKSIZE +1] =  "v3guWjHnXCOmZkw=";


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


QString MainWindow::getCPUID()
{
    QString cpu_id = "";
    QProcess p(nullptr);
    p.start("wmic CPU get ProcessorID");
    p.waitForStarted();
    p.waitForFinished();
    cpu_id = QString::fromLocal8Bit(p.readAllStandardOutput());
    cpu_id = cpu_id.remove("ProcessorId").trimmed();
    return cpu_id;
}

string MainWindow::stdStringToHexString(string str)
{
    #define toASCII(x) ((x) >= 0x0a) ? ((x)+0x37) : ((x)+0x30)

    string result = "";
    for(size_t i=0; i<str.size(); i++)
    {
        byte msb = (str.at(i)>>4)&0x0f;
        byte lsb = str.at(i)&0x0f;
        result += static_cast<char>(toASCII(msb));
        result += static_cast<char>(toASCII(lsb));
    }
    return result;
}

string MainWindow::hexStringToStdString(string str)
{
    #define toNumber(x) (static_cast<byte>(((x) >= 'A') ? ((x)-0x37) : ((x)-0x30)))

    string result="";
    for(size_t i=0; i<str.size(); i+=2)
    {
        byte msb = static_cast<byte>(str.at(i));
        byte lsb = static_cast<byte>(str.at(i+1));
        byte no  = static_cast<byte>((toNumber(msb)<<4) | toNumber(lsb));

        result += static_cast<char>(no);
    }
    return result;
}


string MainWindow::aesEnc(string plaintext)
{
    //encryption
    string strEncTxt;
    CBC_Mode<AES>::Encryption aes_enc(aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH, aes_iv);
    StringSource( plaintext, true, new StreamTransformationFilter( aes_enc, new StringSink( strEncTxt ), BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING, true) );
    return strEncTxt;
}
string MainWindow::aesDec(string ciphertext)
{
    //decryption
    string strDecTxt;
    CBC_Mode<AES>::Decryption aes_dec(aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH, aes_iv);
    StringSource( ciphertext, true, new StreamTransformationFilter( aes_dec, new StringSink( strDecTxt ), BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING, true));
    return strDecTxt;
}


//------------------------
// 定义全局的随机数池
//------------------------
RandomPool & MainWindow::GlobalRNG()
{
    static RandomPool randomPool;
    return randomPool;
}
//------------------------
// 生成RSA密钥对
//------------------------
void MainWindow::GenerateRSAKey(unsigned int keyLength, const char *privFileName, const char *pubFileName, const char *seed)
{
    RandomPool randPool;
    randPool.Put(reinterpret_cast<const byte *>(seed), strlen(seed));

    RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
    HexEncoder privFile(new FileSink(privFileName));

    priv.DEREncode(privFile);
    privFile.MessageEnd();

    RSAES_OAEP_SHA_Encryptor pub(priv);
    HexEncoder pubFile(new FileSink(pubFileName));
    pub.DEREncode(pubFile);

    pubFile.MessageEnd();
}
//------------------------
// RSA加密
//------------------------
string MainWindow::RSAEncryptString( const char *pubFilename, const char *seed, const char *message )
{
    FileSource pubFile( pubFilename, true, new HexDecoder );
    RSAES_OAEP_SHA_Encryptor pub( pubFile );

    RandomPool randPool;
    randPool.Put(reinterpret_cast<const byte *>(seed), strlen(seed) );

    string result;
    StringSource( message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))) );

    return result;
}
//------------------------
// RSA解密
//------------------------
string MainWindow::RSADecryptString( const char *privFilename, const char *seed, const char *ciphertext )
{
    FileSource privFile( privFilename, true, new HexDecoder );
    RSAES_OAEP_SHA_Decryptor priv(privFile);

    //string result;
    //StringSource( ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))) );
    RandomPool randPool;
    randPool.Put(reinterpret_cast<const byte *>(seed), strlen(seed) );

    string result;
    StringSource( ciphertext, true, new PK_DecryptorFilter(randPool, priv, new HexEncoder(new StringSink(result))) );

    return result;
}

void MainWindow::on_pbGenerateSn_clicked()
{
    string message;
    QString cpuid_string = ui->leCPUID->text();
    message = cpuid_string.toStdString();
    if(ui->cbExpire->isChecked())
    {
        message += "+++";
        message += ui->dteExpire->dateTime().toString("yyyy-MM-dd hh:mm:ss").toStdString();
    }
    else
    {
        message += "+++";
        message += QString("0000-00-00 00:00:00").toStdString();
    }
    string encMessage;

    try {
        encMessage = aesEnc(message);
    } catch (...) {
        QMessageBox::warning(this, QString("ERROR"), QString("Message Decrypt error!"));
        return ;
    }

    ui->pteSerialNumberGen->setPlainText(QString::fromStdString(stdStringToHexString(encMessage)));
}

void MainWindow::on_pbCpuidDt_clicked()
{
    string encMessage, decMessage;
    encMessage = hexStringToStdString(ui->pteSerialNumberGen->toPlainText().toStdString());
    try {
        decMessage = aesDec(encMessage);
    } catch (...) {
        QMessageBox::warning(this, QString("ERROR"), QString("Message Encrypt error!"));
        return ;
    }

    QStringList messageList = QString::fromStdString(decMessage).split("+++");
    if(messageList.count() != 2)
    {
        QMessageBox::warning(this, QString("ERROR"), QString("Message parses error!"));
        return ;
    }
    QString cpuidString = messageList.at(0);
    QString datetimeString = messageList.at(1);

    QDateTime dt_fromMessage = QDateTime::fromString(datetimeString, "yyyy-MM-dd hh:mm:ss");
    ui->leCPUID->setText(cpuidString);
    if(dt_fromMessage.toSecsSinceEpoch() <= QDateTime::fromString("2019-01-01 00:00:00").toSecsSinceEpoch())
    {
        ui->cbExpire->setChecked(false);
        ui->dteExpire->setDateTime(dt_fromMessage);
    }
    else
    {
        ui->cbExpire->setChecked(true);
        ui->dteExpire->setDateTime(dt_fromMessage);
    }
}

void MainWindow::on_pbCreateRSAKeys_clicked()
{
    char pubFileName[1024] = {"pub.txt"};
    char privFileName[1024] = {"priv.txt"};
    const char *seed = "seed";//QTime::currentTime().toString("hh:mm:ss").toStdString().data();
    GenerateRSAKey(1024, privFileName, pubFileName, seed);
}

void MainWindow::on_pbGenerate_clicked()
{
    try {
        const char *message = ui->pteSerialNumberIn->toPlainText().toStdString().data();
        const char *seed = QTime::currentTime().toString("hh:mm:ss").toStdString().data();
        string encMessage = RSAEncryptString("pub.txt", seed, message);
        ui->pteAuthCode->setPlainText(QString::fromStdString(encMessage));
    } catch (...) {
        QMessageBox::warning(this, QString("ERROR"), QString("Message RAS encrypt error!"));
        return ;
    }
}

void MainWindow::on_pbVerify_clicked()
{
    try {
        string str = ui->pteAuthCode->toPlainText().toStdString();
        const char *message = str.data();
        qDebug() << message;
        const char *seed = "seed";//QTime::currentTime().toString("hh:mm:ss").toStdString().data();
        string decMessage = RSADecryptString("priv.txt", seed, message);
        ui->pteSerialNumberIn->setPlainText(QString::fromStdString(decMessage));
        qDebug() << QString::fromStdString(decMessage);
    } catch (...) {
        QMessageBox::warning(this, QString("ERROR"), QString("Message RAS decrypt error!"));
        return ;
    }
}
