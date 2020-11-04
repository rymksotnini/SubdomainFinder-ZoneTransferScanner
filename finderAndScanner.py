import socket
import subprocess
import sys

def menu():
	print("[1] find subdomains")
	print("[2] scan for zone transfer vulnerability")
	print("[0] exit")
	
def hostname_resolves(hostname):
	try:
		socket.gethostbyname(hostname)
		return 1
	except socket.error:
		return 0
		
def find_subdomains(domain):
	try:
		fp = open('subdomains-100.txt', 'r')
		for subdomain in fp:
			if hostname_resolves(subdomain.rstrip()+'.'+domain):
				print(subdomain.rstrip()+'.'+domain)

		print("Finished!")

	finally:
		fp.close()
		
def scan_zt(domain):
	p = subprocess.Popen(["host", "-t", "ns", domain], stdout=subprocess.PIPE)
	output, err = p.communicate()
	output=output.decode("utf-8")
	res=output.split('\n')
	del res[-1]
	ns=[]
	for r in res:
    		ns.append(r.split()[-1][:-1])
    		
	print("Testing on the found name servers")
	for n in ns:
    		p = subprocess.Popen(["host", "-l", domain, n], stdout=subprocess.PIPE)
    		output, err = p.communicate()
    		output=output.decode("utf-8")
    		if "failed" in output:
    			print ("{} is not vulnerable to zone transfer".format(n))
    		else:
    			print ("{} is vulnerable to zone transfer".format(n))
    			

domain=input("write your domain: ")

while(True):
	menu()
	option=int(input("Enter your option: "))
	if(option == 1):
		find_subdomains(domain)
	elif(option == 2):
		scan_zt(domain)
	elif(option==0):
		sys.exit("Exiting program...")
	else:
		print("not a valid option")
