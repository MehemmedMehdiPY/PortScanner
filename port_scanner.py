import nmap
import argparse as ap

def print_host_info(host_state, *info):
    if info:
        nm, host, target_address, target_name = info

    print('----------------------------------------------------')
    if host_state == 'up':
        print('Host:  {} ({})'.format(target_address, target_name))
        print('State: {}'.format(host_state))
    else:
        print("Host is down")

parser = ap.ArgumentParser(description='Port Scanning Tool')
parser.add_argument('--host', action = 'store', dest = 'host', required=True)
parser.add_argument('-p', action = 'store', dest = 'port', required=True)

args = parser.parse_args()

targets = args.host.split(',')
begin, end = args.port.split('-')
nm = nmap.PortScanner()

for host in targets:
    try:
        res = nm.scan(host, f'{begin}-{end}') # Results of scan

        host_info = res['scan'][host]
        target_name = host_info['hostnames'][0]['name']  # Target's name
        target_address = host_info['addresses']['ipv4']  # Target's ip address

    except KeyError:
        print_host_info('down')
    
    else:
        # When target name not found,
        if not target_name:
            target_name = 'unknown'
        
        print_host_info(nm[host].state(), nm, host, target_address, target_name)
        print('----------')

        for protocol in nm[host].all_protocols():
            print('Protocol: {}'.format(protocol))
            
            protocol_info = host_info[protocol]
            for port in protocol_info:
                port_info = protocol_info[port]
                print('Port: {}({})\tstate  {}'.format(port, port_info['name'], port_info['state']))

        print()