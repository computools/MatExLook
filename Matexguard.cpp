#include "MatexGuard.h"
#include <QCryptographicHash>


namespace
{

QString generateKeyHash(const QString& key, const QString& salt){
    QByteArray data;
    data.append(key.toUtf8());
    data.append(salt.toUtf8());
    data = QCryptographicHash::hash( data, QCryptographicHash::Sha1 ).toHex();
    return data;
}

}


MatexGuard::MatexGuard(const QString& key)
    : _key(key),
      _memLockKey(generateKeyHash(key, QString("MATEXLOOK") + "_memLockKey")),
      _sharedmemKey(generateKeyHash(key, QString("MATEXLOOK" )+ "_sharedmemKey")),
      _sharedMem(_sharedmemKey),
      _memLock(_memLockKey, 1)
{
    _memLock.acquire();
    {
        QSharedMemory fix(_sharedmemKey);    
        fix.attach();
    }
    _memLock.release();
}

MatexGuard::~MatexGuard(){
    release();
}

bool MatexGuard::isAnotherRunning()
{
    if (_sharedMem.isAttached())
        return false;

    _memLock.acquire();
    const bool isRunning = _sharedMem.attach();
    if (isRunning)
        _sharedMem.detach();
    _memLock.release();

    return isRunning;
}

bool MatexGuard::tryToRun()
{
    if ( isAnotherRunning() )   // Extra check
        return false;

    _memLock.acquire();
    const bool result = _sharedMem.create( sizeof( quint64 ) );
    _memLock.release();
    if ( !result )
    {
        release();
        return false;
    }

    return true;
}

void MatexGuard::release()
{
    _memLock.acquire();
    if ( _sharedMem.isAttached() )
        _sharedMem.detach();
    _memLock.release();
}
