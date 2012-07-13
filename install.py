import os
import subprocess
import socket
import fcntl
import struct
import urllib
import sys
import getpass
from subprocess import Popen

global rem_file
global loc_file
global message
global user
global master_ip
global ret_ip

def this_ip(ifname):
	soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(soc.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def dlProgress(count, blockSize, totalSize):
	percent = int(count*blockSize*100/totalSize)
	sys.stdout.write("\r" + message + "%d%%]" % percent)
	sys.stdout.flush()

#Future: Combine following define "insert" methods
def insertRootRhost():
	master_in_file = False
	slave_in_file = False
	directory = "/root/.rhosts"
	this_user = "root"
	for line in open(directory):
		if "Master " + this_user in line:
			master_in_file = True
		if "Slave " + this_user in line:
			slave_in_file = True
	with open(directory, "a") as rhosts:
		if master_in_file == False:
			rhosts.write("\nMaster " + this_user)
		if slave_in_file == False:
			rhosts.write("\nSlave " + this_user)

def insertMasterRhost(master_user_add):
	directory = "/home/" + master_user_add + "/.rhosts"
	master_in_file = False
	for line in open(directory):
		if "Master " + master_user_add in line:
			master_in_file = True
	with open(directory, "a") as rhosts:
		if master_in_file == False:
			rhosts.write("\nMaster " + master_user_add)
	
def insertUserRhost(user_add):
	directory = "/home/" + user + "/.rhosts"
	slave_in_file = False
	for line in open(directory):
		if "Slave " + user_add in line:
			slave_in_file = True
	with open(directory, "a") as rhosts:
		if slave_in_file == False:
			rhosts.write("\nSlave " + user_add)
			
def insertUserHost(host_ip_add):
	directory = "/etc/hosts"
	slave_ip_in_file = False
	for line in open(directory):
		if host_ip_add + " Slave" in line:
			slave_ip_in_file = True
	with open(directory, "a") as hosts:
		if slave_ip_in_file == False:
			hosts.write("\n" + host_ip_add + " Slave")

def insertHostAllow(host_ip_allow):
	directory = "/etc/hosts.allow"
	host_already_allowed = False
	for line in open(directory):
		if host_ip_allow in line:
			host_already_allowed = True	
	with open(directory, "a") as allowed:
		if host_already_allowed == False:
			allowed.write("\n" + host_ip_allow)

def insertMasterHost(master_ip_add):
	directory = "/etc/hosts"
	master_ip_in_file = False
	for line in open(directory):
		if master_ip_add + " Master" in line:
			master_ip_in_file = True
	with open(directory, "a") as hosts:
		if master_ip_in_file == False:
			hosts.write("\n" + master_ip_add + " Master")

def insertSectretty():
	directory = "/etc/securetty"
	securetty_root_string = "rsh, rlogin, rexec, pts/0, pts/1"
	securetty_in_file = False
	for line in open(directory):
		if securetty_root_string in line:
			securetty_in_file = True
	with open(directory, "a") as securetty:
		if securetty_in_file == False:
			securetty.write("\n" + securetty_root_string)
			
def getIP():
	getting_ip = True
	adap_count = 0
	wlan_test = False
	while getting_ip:
		if wlan_test == False:
			adaptor = "eth" + str(adap_count)
		else:
			adaptor = "wlan" + str(adap_count)

		print "Trying connection on " + adaptor + "..."
		try:
			ret_ip = this_ip(adaptor)
			print "Connection found on " + adaptor
			getting_ip = False
		except IOError:
			print "Error: Failed on eth" + adap_count
		if adap_count == 5:
			adap_count = 0
			if wlan_test == False:
				wlan_test = True
			else:
				new_adap = True
				new_adap_name = raw_input("Error: Cannot find connection. Specify adaptor name:")
				while new_adap:
					try: 
						ret_ip = this_ip(new_adap_name)
						new_adap = False
						getting_ip = False
						print "Connection found on " + new_adap_name
					except IOError:
						new_adap_name = raw_input("Error: Cannot find specified adaptor. Specify another or type \"c\" to exit:")
						if new_adap_name == "c":
							sys.exit()
		return ret_ip

def insertRshContent():
	auth1_text = "auth sufficient /lib/security/pam_nologin.so"
	auth2_text = "auth optional /lib/security/pam_securetty.so"
	auth3_text = "auth sufficient /lib/security/pam_env.so"
	auth4_text = "auth sufficient /lib/security/pam_rhosts_auth.so"
	account_text = "account sufficient /lib/security/pam_stack.so service=system-auth"
	session_text = "session sufficient /lib/security/pam_stack.so service=system-auth"
	directory = "/etc/pam.d/rsh"
	auth1_text_bool = False
	auth2_text_bool = False
	auth3_text_bool = False
	auth4_text_bool = False
	account_text_bool = False
	session_text_bool = False
	for line in open(directory):
		if auth1_text in line:
			auth1_text_bool = True
		if auth2_text in line:
			auth2_text_bool = True
		if auth3_text in line:
			auth3_text_bool = True
		if auth4_text in line:
			auth4_text_bool = True			
		if account_text in line:
			account_text_bool = True
		if session_text in line:
			session_text_bool = True
	with open(directory, "a") as rsh:
		if auth1_text_bool == False:
			rsh.write("\n" + auth1_text)
		if auth2_text_bool == False:
			rsh.write("\n" + auth2_text)
		if auth3_text_bool == False:
			rsh.write("\n" + auth3_text)
		if auth4_text_bool == False:
			rsh.write("\n" + auth4_text)
		if account_text_bool == False:	
			rsh.write("\n" + account_text)
		if session_text_bool == False:
			rsh.write("\n" + session_text)
			
clear = Popen(["clear"])
waitclear = clear.wait()
user = getpass.getuser()
if user != "root":
	print "Error: Please run the script as root. Type \"sudo !!\" to run the last command as root."
	sys.exit()

print "==============MPICH2 v1.4.1 Python Installation Script v0.1 for RPi=============="
print "Please ensure that your IPs are statically allocated to your nodes on the bramble"
print "Dynamic allocation will cause IPs in config files to become redundant. Files will"
print "not be overwritten if they already exist, so don't worry about loosing any data. "
print "=================================================================================\n"
user = raw_input("Please enter your RPi (non root) username: ")

#Assign Popen commands to variable for future error analysing if needed
print "Creating /home/" + user + "/.rhosts file..."
touch = Popen(["touch", "/home/" + user + "/.rhosts"])
c1 = touch.wait()
print "Successfully created /home/" + user + "/.rhosts file"
print "Creating /root/.rhosts file..."
root_touch = Popen(["sudo", "touch", "/root/.rhosts"])
c2 = root_touch.wait()
print "Successfully created /root/.rhosts file"
print "Creating /etc/pam.d/rsh file..."
rshFile = Popen (["touch", "/etc/pam.d/rsh"])
createRsh = rshFile.wait()
print "Successfully created /etc/pam.d/rsh"
print "Creating /etc/hosts file..."
hostsFile = Popen(["touch", "/etc/hosts"])
createHostsFile = hostsFile.wait()
print "Successfully created /etc/hosts"
print "Creating /etc/hosts.allow file..."
allowedHostsFile = Popen(["touch", "/etc/hosts.allow"])
createallowedHosts = allowedHostsFile.wait()
print "Successfully created /etc/hosts.allow"
print "Creating /etc/securetty file..."
securettyFile = Popen(["touch", "/etc/securetty"])
createScuretty = securettyFile.wait()
print "Successfully created /etc/securetty\n"

insertRshContent()
insertSectretty()

master_slave = raw_input("Is this the Master or a Slave node? [M/S]: ")
while master_slave not in ["M", "S"]:
	master_slave = raw_input("Error: \"" + master_slave + "\" not a selection. Is this the Master or a Slave node? [M/S]: ")

if master_slave in "M":
	insertMasterRhost(user)
	insertRootRhost()
	master_ip = getIP()
	insertMasterHost(master_ip)			
	print "IP address is: " + master_ip
	print ""
	
	done = False
	Error = False
	while True:
		try:
			if Error == False:
				loop_count = int(raw_input("Enter number of Slave nodes: "))
			else:
				loop_count = int(raw_input("Error: Not a number. Enter number of Slave nodes: "))
			break
		except (SyntaxError, ValueError, NameError):
			Error = True
	
	print ""	
	count = 0
	while count < loop_count:
		if count == 0:
			current_usr = raw_input("Enter username for first Slave node: ")
		else:
			current_usr = raw_input("Enter username for next Slave node: ")
			
		ip_valid = False
		bad_ip = False
		while ip_valid == False:
			if bad_ip == True:
				current_ip = raw_input("Error: Invalid IPv4 address. Enter IP for Slave node " + current_usr + ": ")
			else:
				current_ip = raw_input("Enter IP for Slave node " + current_usr + ": ")
			try:
				socket.inet_aton(current_ip)
				if len(current_ip.split(".")) == 4:
					ip_valid = True
				else:
					bad_ip = True
			except socket.error:
				bad_ip = True
		
		insertUserHost(current_ip)
		insertUserRhost(current_usr)
		insertHostAllow(current_ip)
		
		print ""
		count += 1
	
elif master_slave in "S":	
	insertRootRhost()
	this_slave_ip = getIP()	
	print "IP address is: " + this_slave_ip
	print ""
	master_user = raw_input("Master node username: ")
	master_ip = raw_input("Master node IP address: ")
	
	insertMasterRhost(master_user)
	insertMasterHost(master_ip)
	insertUserHost(this_slave_ip)
	insertHostAllow(master_ip)
	
	done = False
	Error = False
	not_answer = False
	while True:
		if not not_answer: 
			other_nodes = raw_input("\nIs this the only Slave node? [Y/N]: ")
		else: 
			other_nodes = raw_input("Error: " + other_nodes + " not an selection. Is this the only Slave node? [Y/N]: ")
		if other_nodes == "N":
			while True:
				try:
					if Error == False:
						loop_count = int(raw_input("Enter number of other Slave nodes (not including this node): "))
					else:
						loop_count = int(raw_input("Error: Not a number. Enter number of Slave nodes (not including this node): "))
					break
				except (SyntaxError, ValueError, NameError):
					Error = True
			break
			
		elif other_nodes == "Y":
			loop_count = 0
			break

		else:
			not_answer = True
	
	print ""	
	count = 0
	while count < loop_count:
		if count == 0:
			current_usr = raw_input("Enter username for first Slave node (not including this node): ")
		else:
			current_usr = raw_input("Enter username for next Slave node (not including this node): ")
			
		ip_valid = False
		bad_ip = False
		while ip_valid == False:
			if bad_ip == True:
				current_ip = raw_input("Error: Invalid IPv4 address. Enter IP for Slave node " + current_usr + ": ")
			else:
				current_ip = raw_input("Enter IP for Slave node " + current_usr + ": ")
			try:
				socket.inet_aton(current_ip)
				if len(current_ip.split(".")) == 4:
					ip_valid = True
				else:
					bad_ip = True
			except socket.error:
				bad_ip = True
		insertUserHost(current_ip)
		insertUserRhost(current_usr)
		insertHostAllow(current_ip)
		print ""
		count += 1
		
	
if not os.path.isfile("/home/" + user + "/mpich2_1.4.1p1-1_armel.deb"):
	sys.stdout.write("Downloading MPICH2 .deb package [0%]")	
	sys.stdout.flush()
	message = "Downloading MPICH2 .deb package ["
	rem_file = "https://github.com/downloads/philleonard/MPICH2-Armel-Raspberry-Pi/mpich2_1.4.1p1-1_armel.deb"
	loc_file = "/home/" + user + "/mpich2_1.4.1p1-1_armel.deb"	
	urllib.urlretrieve(rem_file, loc_file, reporthook=dlProgress)
	print ""
	print "Successfully downloaded package\n" 
else:
	print "Skipping download. mpich2_1.4.1p1-1_armel.deb already exists.\n" 

print "Depackaging and installing .deb..."
dpkg = Popen(["sudo", "dpkg", "-i", "mpich2_1.4.1p1-1_armel.deb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
c4 = dpkg.wait()
print "Successfully installed package\n"

if not os.path.isfile("/home/" + user + "/cpi_test.tar.gz"):
	sys.stdout.write("Downloading C test files tarball: [0%]")	
	sys.stdout.flush()
	message = "Downloading C test files tarball: ["
	rem_file = "https://github.com/downloads/philleonard/MPICH2-Armel-Raspberry-Pi/cpi_test.tar.gz"
	loc_file = "/home/" + user + "/cpi_test.tar.gz"
	urllib.urlretrieve(rem_file, loc_file, reporthook=dlProgress)
	print ""
	print "Successfully downloaded cpi_test.tar.gz\n" 
else:
	print "Skipping download. cpi_test.tar.gz already exists.\n"	

print "Untaring cpi_test.tar.gz..."
untar = Popen(["tar", "-zxvf", "/home/" + user + "/cpi_test.tar.gz"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
untarWait = untar.wait()
print "Successfully extracted test files."
print "\nInstallation on this node complete!"
