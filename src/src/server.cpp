/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Nathan Osman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <QtGlobal>

#ifdef Q_OS_UNIX
#  include <cerrno>
#  include <cstring>
#  include <sys/socket.h>
#endif

#include <QHostAddress>
#include <QMap>
#include <QNetworkInterface>

#include <qmdnsengine/dns.h>
#include <qmdnsengine/mdns.h>
#include <qmdnsengine/message.h>
#include <qmdnsengine/server.h>

#include "server_p.h"

using namespace QMdnsEngine;

ServerPrivate::ServerPrivate(Server *server)
    : QObject(server),
      q(server)
{
    filterInterfacesForMulticast();
    connect(&timer, &QTimer::timeout, this, &ServerPrivate::onTimeout);
    connect(&ipv4Socket, &QUdpSocket::readyRead, this, &ServerPrivate::onReadyRead);
    connect(&ipv6Socket, &QUdpSocket::readyRead, this, &ServerPrivate::onReadyRead);

    timer.setInterval(60 * 1000);
    timer.setSingleShot(true);
    onTimeout();
}

bool ServerPrivate::bindSocket(QUdpSocket &socket, const QHostAddress &address)
{
    // Exit early if the socket is already bound
    if (socket.state() == QAbstractSocket::BoundState) {
        return true;
    }

    // I cannot find the correct combination of flags that allows the socket
    // to bind properly on Linux, so on that platform, we must manually create
    // the socket and initialize the QUdpSocket with it

#ifdef Q_OS_UNIX
    if (!socket.bind(address, MdnsPort, QAbstractSocket::ShareAddress)) {
        int arg = 1;
        if (setsockopt(socket.socketDescriptor(), SOL_SOCKET, SO_REUSEADDR,
                reinterpret_cast<char*>(&arg), sizeof(int))) {
            emit q->error(strerror(errno));
            return false;
        }
#endif
        if (!socket.bind(address, MdnsPort, QAbstractSocket::ReuseAddressHint)) {
            emit q->error(socket.errorString());
            return false;
        }
#ifdef Q_OS_UNIX
    }
#endif

    return true;
}

void ServerPrivate::writeMulticastDatagram(QUdpSocket &socket, const QByteArray &datagram, const QHostAddress &host, quint16 port)
{
    for (const auto &iface : qAsConst(m_goodInterfacesForMulticast)) {
        socket.setMulticastInterface(iface);
        socket.writeDatagram(datagram, host, port);
    }
}

void ServerPrivate::filterInterfacesForMulticast()
{
    const QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    QMap<QString, QNetworkInterface> goodIfaces;
    for (const QNetworkInterface &iface : interfaces) {
        if (!(iface.flags() & QNetworkInterface::IsUp) || !(iface.flags() & QNetworkInterface::IsRunning) ||
            (iface.flags() & QNetworkInterface::IsLoopBack) || !(iface.flags() & QNetworkInterface::CanMulticast)) {
            continue;
        }
        const QList<QNetworkAddressEntry> entries = iface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries) {
            if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol &&
                entry.ip().protocol() != QAbstractSocket::IPv6Protocol) {
                continue;
            }
            const QString ip = entry.ip().toString();
            if (ip.startsWith("169.254.")) {
                continue;
            }
            goodIfaces[iface.name()] = iface;
        }
    }
    m_goodInterfacesForMulticast = goodIfaces.values();
}

void ServerPrivate::onTimeout()
{
    // A timer is used to run a set of operations once per minute; first, the
    // two sockets are bound - if this fails, another attempt is made once per
    // timeout; secondly, all network interfaces are enumerated; if the
    // interface supports multicast, the socket will join the mDNS multicast
    // groups

    bool ipv4Bound = bindSocket(ipv4Socket, QHostAddress::AnyIPv4);
    bool ipv6Bound = bindSocket(ipv6Socket, QHostAddress::AnyIPv6);

    if (ipv4Bound || ipv6Bound) {
        const auto interfaces = QNetworkInterface::allInterfaces();
        for (const QNetworkInterface &networkInterface : interfaces) {
            if (networkInterface.flags() & QNetworkInterface::CanMulticast) {
                if (ipv4Bound) {
                    ipv4Socket.joinMulticastGroup(MdnsIpv4Address, networkInterface);
                }
                if (ipv6Bound) {
                    ipv6Socket.joinMulticastGroup(MdnsIpv6Address, networkInterface);
                }
            }
        }
    }

    timer.start();
}

void ServerPrivate::onReadyRead()
{
    // Read the packet from the socket
    QUdpSocket *socket = qobject_cast<QUdpSocket*>(sender());
    QByteArray packet;
    packet.resize(socket->pendingDatagramSize());
    QHostAddress address;
    quint16 port;
    socket->readDatagram(packet.data(), packet.size(), &address, &port);

    // Attempt to decode the packet
    Message message;
    if (fromPacket(packet, message)) {
        message.setAddress(address);
        message.setPort(port);
        emit q->messageReceived(message);
    }
}

Server::Server(QObject *parent)
    : AbstractServer(parent),
      d(new ServerPrivate(this))
{
}

void Server::sendMessage(const Message &message)
{
    QByteArray packet;
    toPacket(message, packet);
    if (message.address().protocol() == QAbstractSocket::IPv4Protocol) {
        d->writeMulticastDatagram(d->ipv4Socket, packet, message.address(), message.port());
    } else {
        d->writeMulticastDatagram(d->ipv6Socket, packet, message.address(), message.port());
    }
}

void Server::sendMessageToAll(const Message &message)
{
    QByteArray packet;
    toPacket(message, packet);
    d->writeMulticastDatagram(d->ipv4Socket, packet, MdnsIpv4Address, MdnsPort);
    d->writeMulticastDatagram(d->ipv6Socket, packet, MdnsIpv6Address, MdnsPort);
}
