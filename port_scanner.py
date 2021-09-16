import nmap
import argparse as ap

def initialize_parser():
    # Initializing command-line parsing module
    parser = ap.ArgumentParser(description='Port Scanning Tool')
    parser.add_argument('--host', action = 'store', dest = 'host', required=True)
    parser.add_argument('-p', action = 'store', dest = 'port', required=True)
    args = parser.parse_args()

    return args

def print_host_info(host_state, *info):
    # The function to print information about the host.

    # If is not empty, arguments got from the list, info.
    if info:
        nm, host, target_address, target_name = info

    print('----------------------------------------------------')
    if host_state == 'up':
        print('Host:  {} ({})'.format(target_address, target_name))
        print('State: {}'.format(host_state))
    else:
        print("Host is down")

def get_scan_results(host_info):
    target_name = host_info['hostnames'][0]['name']  # Target's name
    target_address = host_info['addresses']['ipv4']  # Target's ip address
    return target_name, target_address


def print_protocol_port_info(nm, host):
    # Printing protocols and then their ports in another function.

    print('----------')
    for protocol in nm[host].all_protocols():
        print('Protocol: {}'.format(protocol))

        protocol_info = host_info[protocol] # Getting protocol type
        print_port_info(protocol_info)

def print_port_info(protocol_info):
    # Printing ports of protocol

    for port in protocol_info:
        port_info = protocol_info[port] # Getting port info
        print('Port: {}({})\t\t\t{}'.format(port, port_info['name'], 'state  ' + port_info['state']))

args = initialize_parser()

targets = args.host.split(',')
begin, end = args.port.split('-')

nm = nmap.PortScanner()

for host in targets:
    try:
        res = nm.scan(host, f'{begin}-{end}') # Results of scan

        host_info = res['scan'][host]
        target_name, target_address = get_scan_results(host_info)

    except KeyError:
        print_host_info('down')
    
    else:
        # When target name not found,
        if not target_name:
            target_name = 'unknown'
        
        # Printing host information
        print_host_info(nm[host].state(), nm, host, target_address, target_name)

        # Printing Protocol and port information
        print_protocol_port_info(nm, host)

    finally:
        print()