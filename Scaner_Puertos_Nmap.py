#!/usr/bin/env python 3 
#_*_ coding: utf8 _*_

import nmap 

print()
print("*********************************")
print("     __________     _______      ")
print("    |___    ___|   |   ____|     ")
print("        |  |       |  |          ")
print("     _  |  |       |  |          ")
print("    | |_|  |  _    |  |____      ")
print("    |______| (_)   |_______|     ")
print("*********************************")
print()

print("Script para Escaner Puertos Abiertos de una IP")
print("**************************************************************")
print("Introdusca una IP con el Rango a escanear [192.168.99.41] :)  ")
print("--------------------------------------------------------------")
print("**************************************************************")

def main():
	ip = input("[+] IP $.- ")
	nm = nmap.PortScanner()
	puertos_abiertos = " "
	result = nm.scan(hosts=ip, arguments="-sT -sU -Pn -F -sV")
	count = 0

#	print(results)

	print("\nHost : %s" % ip)
	print("State : %s" % nm[ip].state())
	for proto in nm[ip].all_protocols():
		print("\nProtocolo : %s" % proto)
		print("---------------------------------------------")

		lport = nm[ip][proto].keys()
		sorted(lport)
		for port in lport:
			print("pot : %s\tstate : %s " % (port, nm[ip][proto][port]["state"]))
			if count==0:
				puertos_abiertos = puertos_abiertos+str(port)
				count = 1
			else:
				puertos_abiertos = puertos_abiertos + "," + str(port)

	print("\n Puertos abiertos: "+ puertos_abiertos + "," + str(ip))


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		exit()
