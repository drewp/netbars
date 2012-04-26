from __future__ import division
# using python-libpcap
import pcap, socket, struct, time, threading, web, simplejson, pkg_resources

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
    def __init__(self, period=5, localSide='1.2.3.4'):
        self.packets = [] # (time, packet)
        self.period = period
        self.localSide = localSide

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
        for p in self._recentPackets():
            bytes = p[1]['original_length']
            key = p[1]['source_address']
            if key == self.localSide:
                key = p[1]['destination_address']
                
            total[key] = total.get(key, 0) + bytes
            allBytes += bytes
            npackets += 1
            times.append(p[0])

        topsPerSec = sorted(
            ((periodBytes // self.period,
              self.hostname(host) if periodBytes > byteThreshold else host)
             for host, periodBytes in total.items()),
            reverse=True)[:n]

        return dict(period=self.period,
                    packets=npackets,
                    bytes=allBytes // self.period,
                    tops=[(h, b) for b, h in topsPerSec])

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
    p.open_live(interface, 1600, 0, 100)
    p.setnonblock(True)
    while 1:
        numRead = p.dispatch(1, save_packet)
        if numRead == 0:
            time.sleep(.1)

class recentPage(object):
    def GET(self):
        """
        n hosts with the most traffic to+from our local host
        """
        n = int(web.input().get('n', '5'))
        web.header('Content-type', 'application/json')
        return simplejson.dumps(recent.recent(n=n))

class traffic(object):
    def GET(self):
        """
        gets the [bytes_in, bytes_out] per second, averaged over the
        last 5 seconds
        """
        web.header('Content-type', 'application/json')
        return simplejson.dumps(recent.traffic())
    
class root(object):
    def GET(self):
        web.header('Content-type', 'text/html')
        return pkg_resources.resource_stream(__name__, "bars.html").read()

recent = RecentActivity(localSide='173.228.113.240')

sniffThread = threading.Thread(target=sniff, args=(recent, "eth2"))
sniffThread.daemon = True
sniffThread.start()

urls = ('/', 'root',
        '/recent', 'recentPage',
        '/traffic', 'traffic')
app = web.application(urls, globals(), autoreload=False)
application = app.wsgifunc()
