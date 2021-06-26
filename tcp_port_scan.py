import optparse
import socket 
import threading


screenLock = threading.Semaphore(value=1)

def connScan(tgtHost, tgtPort):
	
	connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connSkt.settimeout(3)
	resultString = ""

	try:
		connSkt.connect((tgtHost, tgtPort))
		result = True
	except:
		result = False
	'''
	#If you want to get the banner
	if result:
		try:
			connSkt.send('Hey you\r\n')
			resultString = connSkt.recv(100)
		except:
			pass
	connSkt.close()
	'''

	screenLock.acquire()
	if result:
		print('[+] %d /tcp open' %tgtPort)
		print('[+] ' +resultString)
	else:
		print('[-] Port %d/tcp is closed'%tgtPort)

	screenLock.release()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIp = socket.gethostbyname(tgtHost)
	except:
		print("[-] Cannot resolve '%s': Unknown host" %tgtHost)
		return

	try:
		tgtName = gethostbyaddr(tgtIp)
		print('\n[+] Scan results for: ' +tgtName[0])
	except:
		print('\n[+] Scan results for: '+tgtIp)
		socket.setdefaulttimeout(1)
	
	for tgtPort in tgtPorts:
		tgtPort = int(tgtPort.strip())
		t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()

def main():
	parser = optparse.OptionParser('Usage: -H <target host> -p <target port>')

	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] seperated by comma')

	(options, args) = parser.parse_args()

	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')

	if (tgtHost == None) | (tgtPorts[0] == None):
		print(parser.usage)
		exit(0)

	portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	main()