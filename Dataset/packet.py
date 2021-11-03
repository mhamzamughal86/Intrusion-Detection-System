import pyshark
import time 
import random
class Packet:
    packet_list = list()
    def initiating_packets(self):
        self.packet_list.clear()
        capture = pyshark.LiveCapture(interface="Wi-Fi")
        for packet in capture.sniff_continuously(packet_count=25):
            try:
                if "<UDP Layer>" in str(packet.layers) and "<IP Layer>" in str(packet.layers):
                    self.packet_list.append(packet)
                elif "<TCP Layer>" in str(packet.layers) and "<IP Layer>" in str(packet.layers):
                    self.packet_list.append(packet)
            except:
                print(f"No Attribute name 'ip' {packet.layers}")
    def udp_packet_attributes(self,packet):
        attr_list = list()
        a1 = packet.ip.ttl
        a2 = packet.ip.proto
        a3 = self.__get_service(packet.udp.port, packet.udp.dstport)
        a4 = packet.ip.len
        a5 = random.randrange(0,1000)
        a6 = self.__get_land(packet,a2)
        a7 = 0
        a8, a10, a11 = self.__get_count_with_same_and_diff_service_rate(packet.udp.dstport, a3) #23, 29, 30
        a9, a12 = self.__get_srv_count_and_srv_diff_host_rate(packet.ip.dst, a3) #24, 31
        a13, a15, a16 = self.__get_dst_host_count(packet.ip.dst, a3) # 32,34,35
        a14, a17, a18 = self.__get_dst_host_srv_count(packet.udp.port, packet.udp.dstport, packet.ip.dst) #33, 36, 37
        attr_list.extend((a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18))
        return self.get_all_float(attr_list)

    def tcp_packet_attributes(self,packet):
        attr_list = list()
        a1 = packet.ip.ttl #duration
        a2 = packet.ip.proto    #protocol
        a3 = self.__get_service(packet.tcp.port, packet.tcp.dstport) # service
        a4 = packet.ip.len 
        a5 = random.randrange(0,1000)
        a6 = self.__get_land(packet,a2)
        a7 = packet.tcp.urgent_pointer
        a8, a10, a11 = self.__get_count_with_same_and_diff_service_rate(packet.tcp.dstport, a3) #23, 29, 30
        a9, a12 = self.__get_srv_count_and_srv_diff_host_rate(packet.ip.dst, a3) #24, 31
        a13, a15, a16 = self.__get_dst_host_count(packet.ip.dst, a3) # 32,34,35
        a14, a17, a18 = self.__get_dst_host_srv_count(packet.tcp.port, packet.tcp.dstport, packet.ip.dst) #33, 36, 37
        attr_list.extend((a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18))
        return self.get_all_float(attr_list)

    def __get_service(self,src_port,dst_port):
        services = [80,443,53]
        if int(src_port) in services:
            return int(src_port)
        elif int(dst_port) in services:
            return int(dst_port)
        else:
            return 53

    def __get_land(self,packet, protocol):
        if int(protocol) == 6:
            if(packet.ip.dst == packet.ip.src and packet.tcp.port == packet.tcp.dstport):
                return 1
            else:
                return 0
        elif int(protocol) == 17:
            if(packet.ip.dst == packet.ip.src and packet.udp.port == packet.udp.dstport):
                return 1
            else:
                return 0
    
    
    def __get_count_with_same_and_diff_service_rate(self,dst_port, service): #23, 29, 30
        count = 0
        packet_with_same_service = 0
        for p in self.packet_list:
                if "<UDP Layer>" in str(p.layers):
                    if (p.udp.dstport == dst_port):
                        count+=1
                        if (self.__get_service(p.udp.port, p.udp.dstport) == service):
                            packet_with_same_service+=1
                elif "<TCP Layer>" in str(p.layers):
                    if (p.tcp.dstport == dst_port):
                        count+=1
                        if (self.__get_service(p.tcp.port, p.tcp.dstport) == service):
                            packet_with_same_service+=1
        same_service_rate=0.0
        diff_service_rate = 1.0                                                         
        if not count==0:           # To avoid zero divison error
            same_service_rate = ((packet_with_same_service*100)/count)/100
            diff_service_rate = diff_service_rate-same_service_rate
        return (count, same_service_rate, diff_service_rate)

    def __get_srv_count_and_srv_diff_host_rate(self,dst_ip, service): #24, 31
        diff_dst_ip = 0
        service_count = 0
        for p in self.packet_list:
                if "<UDP Layer>" in str(p.layers):
                        if (self.__get_service(p.udp.port, p.udp.dstport) == service):
                            service_count+=1
                            if not (p.ip.dst == dst_ip):           # not added
                                diff_dst_ip+=1
                elif "<TCP Layer>" in str(p.layers):
                    if (self.__get_service(p.tcp.port, p.tcp.dstport) == service):
                            service_count+=1
                            if not (p.ip.dst == dst_ip):            # not added
                                diff_dst_ip+=1
        srv_diff_host_rate = 0.0
        if not(service_count == 0):
            srv_diff_host_rate = ((diff_dst_ip*100)/service_count)/100
        return (service_count, srv_diff_host_rate)

    def __get_dst_host_count(self,dst_ip, service): #32, 34, 35
        same_dst_ip = 0
        same_service=0
        for p in self.packet_list:
            if(p.ip.dst == dst_ip):
                same_dst_ip+=1
                if "<UDP Layer>" in str(p.layers):
                    if (self.__get_service(p.udp.port, p.udp.dstport) == service):
                            same_service+=1
                elif "<TCP Layer>" in str(p.layers):
                    if (self.__get_service(p.tcp.port, p.tcp.dstport) == service):
                            same_service+=1
        dst_host_same_srv_rate = 0.0
        dst_host_diff_srv_rate = 1.0
        if not same_dst_ip==0:
            dst_host_same_srv_rate = ((same_service*100)/same_dst_ip)/100
            dst_host_diff_srv_rate = dst_host_diff_srv_rate-dst_host_same_srv_rate          
        return (same_dst_ip, dst_host_same_srv_rate, dst_host_diff_srv_rate)

    def __get_dst_host_srv_count(self,src_port, dst_port, dst_ip): #33, 36, 37
        dst_host_srv_count = 0
        same_src_port = 0
        diff_dst_ip = 0
        for p in self.packet_list:
            if "<UDP Layer>" in str(p.layers):
                if (p.udp.dstport == dst_port):      # same destination port
                    dst_host_srv_count+=1
                    if (p.udp.port == src_port):    # same src port
                        same_src_port+=1
                    if not (p.ip.dst == dst_ip):         # different destination Ip
                        diff_dst_ip+=1

            elif "<TCP Layer>" in str(p.layers):
                if (p.tcp.dstport == dst_port):     # same destination port
                    dst_host_srv_count+=1
                    if (p.tcp.port == src_port):     # same src port
                        same_src_port+=1
                    if not (p.ip.dst == dst_ip):         #different destination ip
                        diff_dst_ip+=1
        dst_host_same_src_port_rate = 0.0
        dst_host_srv_diff_host_rate = 0.0
        if not dst_host_srv_count==0:
            dst_host_same_src_port_rate = ((same_src_port*100)/dst_host_srv_count)/100
            dst_host_srv_diff_host_rate = ((diff_dst_ip*100)/dst_host_srv_count)/100
        return (dst_host_srv_count, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate)


    def get_all_float(self,l):

        all_float = list()
        for x in l:
            all_float.append(round(float(x),1))
        return all_float