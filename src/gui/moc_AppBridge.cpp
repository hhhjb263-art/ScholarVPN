/****************************************************************************
** Meta object code from reading C++ file 'AppBridge.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.9.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "AppBridge.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'AppBridge.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.9.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN9AppBridgeE_t {};
} // unnamed namespace

template <> constexpr inline auto AppBridge::qt_create_metaobjectdata<qt_meta_tag_ZN9AppBridgeE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "AppBridge",
        "stateChanged",
        "",
        "ConnState",
        "s",
        "connected",
        "ip",
        "logappend",
        "line",
        "tokenRejected",
        "updateChecked",
        "status",
        "action",
        "latest",
        "notes",
        "error",
        "url",
        "sha256",
        "size",
        "downloadProgress",
        "percent",
        "downloadFinished",
        "ok",
        "start",
        "stop",
        "connect_to_server",
        "ServerEntry",
        "entry",
        "check_update",
        "download_and_install",
        "version"
    };

    QtMocHelpers::UintData qt_methods {
        // Signal 'stateChanged'
        QtMocHelpers::SignalData<void(ConnState)>(1, 2, QMC::AccessPublic, QMetaType::Void, {{
            { 0x80000000 | 3, 4 },
        }}),
        // Signal 'connected'
        QtMocHelpers::SignalData<void(const QString &)>(5, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 6 },
        }}),
        // Signal 'logappend'
        QtMocHelpers::SignalData<void(const QString &)>(7, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 8 },
        }}),
        // Signal 'tokenRejected'
        QtMocHelpers::SignalData<void()>(9, 2, QMC::AccessPublic, QMetaType::Void),
        // Signal 'updateChecked'
        QtMocHelpers::SignalData<void(int, int, const QString &, const QString &, const QString &, const QString &, const QString &, quint64)>(10, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 11 }, { QMetaType::Int, 12 }, { QMetaType::QString, 13 }, { QMetaType::QString, 14 },
            { QMetaType::QString, 15 }, { QMetaType::QString, 16 }, { QMetaType::QString, 17 }, { QMetaType::ULongLong, 18 },
        }}),
        // Signal 'downloadProgress'
        QtMocHelpers::SignalData<void(int)>(19, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Int, 20 },
        }}),
        // Signal 'downloadFinished'
        QtMocHelpers::SignalData<void(bool, const QString &)>(21, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::Bool, 22 }, { QMetaType::QString, 15 },
        }}),
        // Slot 'start'
        QtMocHelpers::SlotData<void()>(23, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'stop'
        QtMocHelpers::SlotData<void()>(24, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'connect_to_server'
        QtMocHelpers::SlotData<void(const ServerEntry &)>(25, 2, QMC::AccessPublic, QMetaType::Void, {{
            { 0x80000000 | 26, 27 },
        }}),
        // Slot 'check_update'
        QtMocHelpers::SlotData<void()>(28, 2, QMC::AccessPublic, QMetaType::Void),
        // Slot 'download_and_install'
        QtMocHelpers::SlotData<void(const QString &, const QString &, quint64, const QString &)>(29, 2, QMC::AccessPublic, QMetaType::Void, {{
            { QMetaType::QString, 16 }, { QMetaType::QString, 17 }, { QMetaType::ULongLong, 18 }, { QMetaType::QString, 30 },
        }}),
    };
    QtMocHelpers::UintData qt_properties {
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<AppBridge, qt_meta_tag_ZN9AppBridgeE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject AppBridge::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN9AppBridgeE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN9AppBridgeE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN9AppBridgeE_t>.metaTypes,
    nullptr
} };

void AppBridge::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<AppBridge *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->stateChanged((*reinterpret_cast< std::add_pointer_t<ConnState>>(_a[1]))); break;
        case 1: _t->connected((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 2: _t->logappend((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1]))); break;
        case 3: _t->tokenRejected(); break;
        case 4: _t->updateChecked((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[5])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[6])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[7])),(*reinterpret_cast< std::add_pointer_t<quint64>>(_a[8]))); break;
        case 5: _t->downloadProgress((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 6: _t->downloadFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 7: _t->start(); break;
        case 8: _t->stop(); break;
        case 9: _t->connect_to_server((*reinterpret_cast< std::add_pointer_t<ServerEntry>>(_a[1]))); break;
        case 10: _t->check_update(); break;
        case 11: _t->download_and_install((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<quint64>>(_a[3])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[4]))); break;
        default: ;
        }
    }
    if (_c == QMetaObject::IndexOfMethod) {
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(ConnState )>(_a, &AppBridge::stateChanged, 0))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(const QString & )>(_a, &AppBridge::connected, 1))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(const QString & )>(_a, &AppBridge::logappend, 2))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)()>(_a, &AppBridge::tokenRejected, 3))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(int , int , const QString & , const QString & , const QString & , const QString & , const QString & , quint64 )>(_a, &AppBridge::updateChecked, 4))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(int )>(_a, &AppBridge::downloadProgress, 5))
            return;
        if (QtMocHelpers::indexOfMethod<void (AppBridge::*)(bool , const QString & )>(_a, &AppBridge::downloadFinished, 6))
            return;
    }
}

const QMetaObject *AppBridge::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AppBridge::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN9AppBridgeE_t>.strings))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int AppBridge::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 12)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void AppBridge::stateChanged(ConnState _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 0, nullptr, _t1);
}

// SIGNAL 1
void AppBridge::connected(const QString & _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 1, nullptr, _t1);
}

// SIGNAL 2
void AppBridge::logappend(const QString & _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 2, nullptr, _t1);
}

// SIGNAL 3
void AppBridge::tokenRejected()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void AppBridge::updateChecked(int _t1, int _t2, const QString & _t3, const QString & _t4, const QString & _t5, const QString & _t6, const QString & _t7, quint64 _t8)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 4, nullptr, _t1, _t2, _t3, _t4, _t5, _t6, _t7, _t8);
}

// SIGNAL 5
void AppBridge::downloadProgress(int _t1)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 5, nullptr, _t1);
}

// SIGNAL 6
void AppBridge::downloadFinished(bool _t1, const QString & _t2)
{
    QMetaObject::activate<void>(this, &staticMetaObject, 6, nullptr, _t1, _t2);
}
QT_WARNING_POP
