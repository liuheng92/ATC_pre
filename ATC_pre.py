"""
author: Michael liu (michaelliu92@163.com)
"""
import re
from subprocess import Popen,PIPE,STDOUT
import logging
from select import poll, POLLIN
import multiprocessing
import argparse

IN_INF = 'eno1'
OUT_INF = 'enx000ec6de8983'

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def sh( cmd ):
    "Print a command and send it to the shell"
    logger.info( cmd + '\n' )
    return Popen( [ '/bin/sh', '-c', cmd ], stdout=PIPE ).communicate()[ 0 ]

# This is a bit complicated, but it enables us to
# monitor command output as it is happening

def errRun( *cmd, **kwargs ):
    """Run a command and return stdout, stderr and return code
       cmd: string or list of command and args
       stderr: STDOUT to merge stderr with stdout
       shell: run command using shell
       echo: monitor output to console"""
    # By default we separate stderr, don't run in a shell, and don't echo
    stderr = kwargs.get( 'stderr', PIPE )
    shell = kwargs.get( 'shell', False )
    echo = kwargs.get( 'echo', False )
    if echo:
        # cmd goes to stderr, output goes to stdout
        logger.info( cmd, '\n' )
    if len( cmd ) == 1:
        cmd = cmd[ 0 ]
    # Allow passing in a list or a string
    if isinstance( cmd, str ) and not shell:
        cmd = cmd.split( ' ' )
        cmd = [ str( arg ) for arg in cmd ]
    elif isinstance( cmd, list ) and shell:
        cmd = " ".join( arg for arg in cmd )
    popen = Popen( cmd, stdout=PIPE, stderr=stderr, shell=shell )
    # We use poll() because select() doesn't work with large fd numbers,
    # and thus communicate() doesn't work either
    out, err = '', ''
    poller = poll()
    poller.register( popen.stdout, POLLIN )
    fdtofile = { popen.stdout.fileno(): popen.stdout }
    outDone, errDone = False, True
    if popen.stderr:
        fdtofile[ popen.stderr.fileno() ] = popen.stderr
        poller.register( popen.stderr, POLLIN )
        errDone = False
    while not outDone or not errDone:
        readable = poller.poll()
        for fd, _event in readable:
            f = fdtofile[ fd ]
            data = f.read( 1024 )
            if echo:
                logger.output( data )
            if f == popen.stdout:
                out += data
                if data == '':
                    outDone = True
            elif f == popen.stderr:
                err += data
                if data == '':
                    errDone = True
    returncode = popen.wait()
    return out, err, returncode

def quietRun( cmd, **kwargs ):
    "Run a command and return merged stdout and stderr"
    return errRun( cmd, stderr=STDOUT, **kwargs )[ 0 ]

#Recommend: use after stop your program
#kill dhcp
def kill_dhcp():
    output = re.findall('\d+', sh("netstat -uap | grep dhcpd | awk '{ print $6 }'"))
    if output:
        quietRun('kill %s' % output[0])

#Configure subnet by editing /etc/dhcp/dhcpd.conf
#and /etc/default/isc-dhcp-server
def config_dhcp_subnet():
    # edit /etc/dhcp/dhcpd.conf
    logger.info('make sure you did not have subnet configure'
         ' in your /etc/dhcp/dhcpd.conf file!\n')

    dhcp_conf = '/etc/dhcp/dhcpd.conf'
    #using special line to determine if the configuration exists
    #TODO(michael):if there is a better idea to do this
    line = '\n#michael special code 012345678\n'
    config = open( dhcp_conf ).read()
    if ( line ) not in config:
        logger.info( '*** Adding subnet config to ' + dhcp_conf + '\n' )
        #TODO(michael):ugly ip address and dns address
        with open( dhcp_conf, 'a' ) as f:
            f.write( line )
            f.write( 'subnet 192.168.1.0 netmask 255.255.255.0\n'
                     '{\n'
                     '\trange 192.168.1.2 192.168.1.10;\n'  #ip range
                     '\toption routers 192.168.1.1;\n'      #gateway
                     '\toption domain-name-servers 10.210.97.123,10.210.97.21,10.210.97.61;\n'  #dns
                     '}\n' )

#clean last dhcp config(delete line which includes "INTERFACES=")
def clean_dhcp_inf(dhcp_default):
    with open(dhcp_default, 'r') as f:
        lines = f.readlines()
        # print(lines)
    enter_key = ['\n', '\r\n', '\r']
    with open(dhcp_default, 'w') as f_w:
        for line_index in xrange(len(lines)-1):
            #Debug:checkout enter_key
            # print repr(line)
            if "INTERFACES=" in lines[line_index]:
                continue
            #delete line if there are two "enter"
            if (lines[line_index] in enter_key) and (lines[line_index+1] in enter_key):
                continue
            f_w.write(lines[line_index])

def config_dhcp_intf():
    #edit /etc/default/isc-dhcp-server
    logger.info('make sure you did not have interface configure'
         ' in your /etc/default/isc-dhcp-server file!\n')
    dhcp_default = '/etc/default/isc-dhcp-server'
    clean_dhcp_inf(dhcp_default)
    #use node's port, not switch's port
    #like: line = '\nINTERFACES="OUTINTERFACE"\n'
    line = '\nINTERFACES="%s"\n' % OUT_INF
    logger.info( '*** Adding "' + line.strip() + '" to ' + dhcp_default + '\n' )
    with open( dhcp_default, 'a' ) as f:
        f.write( line )

#test dhcp if it can start(0:yes, 1:no)
def testandstart_dhcp():
    (out, err, returncode) = errRun('dhcpd')
    if returncode:
        logger.error('\n##### dhcpd error! #####\n')
        logger.error(err)
        return 1
    return 0

#Configure NAT
def config_nat():
    # Cleanup iptables rules
    # TODO(michael): not sure . Is it safe ?
    errRun('iptables -X')
    errRun('iptables -F')

    # Create default entries for unmatched traffic
    errRun( 'iptables -P INPUT ACCEPT' )
    errRun( 'iptables -P OUTPUT ACCEPT' )
    errRun( 'iptables -P FORWARD DROP' )

    # Configure NAT
    errRun('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % IN_INF)
    errRun('iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT' % (IN_INF,OUT_INF))
    errRun('iptables -A FORWARD -i %s -o %s -j ACCEPT' % (OUT_INF,IN_INF))

    # Instruct the kernel to support forwarding
    errRun('sysctl net.ipv4.ip_forward=1')

    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    errRun('service network-manager restart')

def checkIntf(hwintf):
    "Make sure hardware interface exists and is not configured."
    if (' %s:' % hwintf) not in quietRun('ip link show'):
        logger.error('Error:', hwintf, 'does not exist!\n')
        exit(1)
    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', quietRun('ifconfig ' + hwintf))
    if ips:
        logger.error('Error:', hwintf, 'has an IP address,'
                              'and is probably in use!\n')
        exit(1)


def start():
    #1.clean all the config
    logger.info('#1.clean all the config\n')
    kill_dhcp()
    #2.configure dhcp for local net IP address
    logger.info('#2.configure dhcp for local net IP address\n')
    config_dhcp_subnet()
    #3.configure dhcp for virtual interface
    logger.info('#3.configure dhcp for virtual interface\n')
    config_dhcp_intf()
    # TODO(michael):ugly ip address
    sh('ifconfig %s 192.168.1.1/24' % OUT_INF)
    #4.configure NAT
    logger.info('#4.configure NAT\n')
    config_nat()
    #5.start dhcpd
    logger.info('#5.start dhcpd\n')
    if testandstart_dhcp():
        exit(1)
    logger.info(sh("netstat -uap | grep dhcpd | awk '{ print $6 }'"))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--flag", dest="flag", default = 0, help="decide if use atc one stage")
    arg = parser.parse_args()

    try:
        start()
        if arg.flag:
            config_atc_arg = 'atcd --atcd-wan %s --atcd-lan %s --atcd-dont-drop-packets' % (IN_INF, OUT_INF)
            run_atc_arg = 'python /home/liuheng/augmented-traffic-control/atcui/manage.py runserver 0.0.0.0:8000'
            config_atc = multiprocessing.Process(target=sh, args=(config_atc_arg,))
            run_atc = multiprocessing.Process(target=sh, args=(run_atc_arg,))
            config_atc.start()
            run_atc.start()
            # sh('atcd --atcd-wan %s --atcd-lan %s --atcd-dont-drop-packets' % (IN_INF, OUT_INF))
    except Exception, e:
        logger.info(str(e) + '\n')
    logger.info('\n############### The end ###############\n')
