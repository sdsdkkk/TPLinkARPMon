import urllib3
import base64

class TPLinkARPMon:
    def __init__(self, router_ip, admin_user, admin_pass):
        self.ip = router_ip
        self.auth_cookie = self.__cookie(admin_user, admin_pass)

    def __cookie(self, admin_user, admin_pass):
        token = base64.b64encode('{}:{}'.format(admin_user, admin_pass).encode('utf-8'))
        return 'Authorization=Basic {}'.format(token)

    def __headers(self):
        return {
            'Cookie': self.auth_cookie,
            'Referer': 'http://{}/mainFrame.htm'.format(self.ip)
        }

    def __target_uri(self):
        return 'http://{}/cgi?5'.format(self.ip)

    def __body(self):
        return '[ARP_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'

    def __parse_arp_data(self, arp_data):
        lines = arp_data.split("\n")
        sections = []
        section_buf = []

        line_count = 0
        for l in lines:
            if line_count % 4 == 0 and line_count > 0:
                sections.append(section_buf)
                section_buf = []
            section_buf.append(l)
            line_count += 1
        sections.append(section_buf)

        return sections

    def __get_devices_info(self, arp_sections):
        devices = []

        for s in arp_sections:
            if len(s) < 4:
                break
            raw_ip = hex(int(s[2][3:]))[2:]
            mac = s[3][4:]
            ip_components = []
            for i in range(0, len(raw_ip), 2):
                ip_component = int(raw_ip[i:i+2], 16)
                ip_components.append(str(ip_component))
            ip = '.'.join(ip_components)

            devices.append((mac, ip))

        return devices

    def connected_devices(self):
        http = urllib3.PoolManager()
        r = http.request('GET', self.__target_uri(), body=self.__body(), headers=self.__headers())
        response = r.data.decode('utf-8')
        arp_sections = self.__parse_arp_data(response)
        devices = self.__get_devices_info(arp_sections)
        return devices
