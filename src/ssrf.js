import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const blockedNetworks = new BlockList();

// RFC 1918, loopback, link-local, documentation, multicast et réseaux réservés.
[
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4]
].forEach(([address, prefix]) => blockedNetworks.addSubnet(address, prefix, 'ipv4'));

[
    ['::', 128],
    ['::1', 128],
    ['fc00::', 7],
    ['fe80::', 10],
    ['ff00::', 8]
].forEach(([address, prefix]) => blockedNetworks.addSubnet(address, prefix, 'ipv6'));

function isBlockedAddress(address, family = isIP(address)) {
    if (!family) return false;
    if (family === 6 && address.toLowerCase().startsWith('::ffff:')) return true;
    return blockedNetworks.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

export async function isSafeOutboundUrl(value, options = {}) {
    const protocols = options.protocols || ['https:'];
    const allowedPorts = options.allowedPorts || ['', '443'];

    try {
        const target = new URL(value);
        const hostname = target.hostname.toLowerCase();
        if (!protocols.includes(target.protocol) || !allowedPorts.includes(target.port) || target.username || target.password) return false;
        if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) return false;
        if (isIP(hostname) && isBlockedAddress(hostname)) return false;

        const addresses = await lookup(hostname, { all: true, verbatim: true });
        const safeAddresses = addresses.every(({ address, family }) => !isBlockedAddress(address, family));
        return addresses.length > 0 && safeAddresses;
    } catch {
        return false;
    }
}
