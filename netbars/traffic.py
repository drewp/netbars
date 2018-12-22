from __future__ import division
# using python-libpcap
import pcap, socket, struct, os, time, threading

# from http://pylibpcap.sourceforge.net/
def decode_ip_packet(s):
  d={}
#  d['version']=(ord(s[0]) & 0xf0) >> 4
#  d['header_len']=ord(s[0]) & 0x0f
#  d['tos']=ord(s[1])
  d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
#  d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
#  d['flags']=(ord(s[6]) & 0xe0) >> 5
#  d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
#  d['ttl']=ord(s[8])
#  d['protocol']=ord(s[9])
#  d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
  d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
  d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
#  if d['header_len']>5:
#    d['options']=s[20:4*(d['header_len']-5)]
#  else:
#    d['options']=None
#  d['data']=s[4*d['header_len']:]
  return d

class RecentActivity(object):
    def __init__(self, period=5, localSide='1.2.3.4', iface='eth0'):
        self.packets = [] # (time, packet)
        self.period = period
        self.localSide = localSide

        sniffThread = threading.Thread(target=sniff, args=(self, iface))
        sniffThread.daemon = True
        sniffThread.start()

    def add(self, timestamp, packet):
        self.packets.append((timestamp, packet))
        if len(self.packets) > 5000:
            self.flushOldPackets()

    def flushOldPackets(self):
        old = time.time() - self.period
        keep = [(t,p) for t,p in self.packets if t > old]
        self.packets = keep

    def recent(self, n=5, byteThreshold=2000):
        """
        return is normalized to avg bytes/sec

        byteThreshold avoids dns lookup for small results

        Initial startup is handled wrong; results will be too low for
        the first 'period' seconds of runtime.
        """
        total = {} # remotehost : bytes (in + out)
        npackets = 0
        times = []
        allBytes = 0
        flow = {} # (src, dest) : bytes
        for p in self._recentPackets():
            bytes = p[1]['original_length']
            key = p[1]['source_address']
            if key == self.localSide:
                key = p[1]['destination_address']
                
            total[key] = total.get(key, 0) + bytes
            allBytes += bytes
            npackets += 1
            times.append(p[0])
            fkey = (p[1]['source_address'], p[1]['destination_address'])
            if fkey not in flow:
              flow[fkey] = 0
            flow[fkey] += p[1]['total_len']

        topsPerSec = sorted(
            ((periodBytes // self.period,
              self.hostname(host) if periodBytes > byteThreshold else host)
             for host, periodBytes in total.items()),
            reverse=True)[:n]

        flowTable = [(nbytes / self.period,
                      self.hostname(src),
                      self.hostname(dst))
                     for (src, dst), nbytes in flow.iteritems()]
        flowTable.sort(key=lambda (n, s, d): (-n, s, d))
        flowTable = flowTable[:10]
        
        return dict(period=self.period,
                    packets=npackets,
                    bytes=allBytes // self.period,
                    tops=[(h, b) for b, h in topsPerSec],
                    flow=flowTable)

    def traffic(self):
        inOut = [0, 0] # total bytes in, out
        for p in self._recentPackets():
            bytes = p[1]['original_length']
            key = p[1]['source_address']
            if key == self.localSide:
                inOut[1] += bytes
            else:
                inOut[0] += bytes
        return int(inOut[0] / self.period), int(inOut[1] / self.period)

    def _recentPackets(self):
        start = time.time() - self.period
        for i, p in enumerate(self.packets[::-1]):
            if p[0] > start:
                yield p
            else:
                self.packets = self.packets[len(self.packets)-i:]
                break
    
    def hostname2(self, ipAddress):
        try:
            # slow!
            ret = socket.getnameinfo((ipAddress, 1), socket.NI_NAMEREQD)[0]
            if ret == 'unknown':
                return ipAddress
            return ret
        except socket.gaierror:
            return ipAddress
        
    def hostname(self, ipAddress):
        try:
            ret = socket.gethostbyaddr(ipAddress)[0]
            if ret == 'unknown':
                return ipAddress
            return ret
        except socket.herror:
            return ipAddress

def sniff(recent, interface):
    def save_packet(pktlen, data, timestamp):
        # from http://pylibpcap.sourceforge.net/
        if not data:
            return

        if data[12:14]=='\x08\x00':
            decoded=decode_ip_packet(data[14:])
            decoded['original_length'] = pktlen
            recent.add(timestamp, decoded)
    p = pcap.pcapObject()
    try:
      p.open_live(interface, 1600, 0, 100)
    except Exception:
      import traceback
      traceback.print_exc()
      os.abort()
    p.setnonblock(True)
    try:
        while 1:
            numRead = p.dispatch(1, save_packet)
            if numRead == 0:
                time.sleep(.01)
    except:
        os.abort()
