#!/usr/bin/python
'''
ver el tema del protection level
http://developer.android.com/guide/topics/manifest/permission-element.html#plevel
'''

import sys
import signal
import os
import re
import subprocess
#import dvm

global Path_aapt
Path_aapt="./aapt"


def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	sys.exit(1)

def signal_exit(signal, frame):
    sys.exit(0)	

def usage ():
		print "\n\tUsage:"
		print "\t\tapk-analyser.python -{a,b,c,d,f i,l,m,p,q,s,u,x} {App}"
		print "\t\t-a\tApp Enumerate Activities"
		print "\t\t-b\tApp Enumerate Broadcast Receiver"
		print "\t\t-c\tApp Enumerate Content Providers"
		print "\t\t-d\tApp Enumerate Data"
		print "\t\t-e\tApp Enumerate Databases"
		print "\t\t-f\tApp Enumerate Features"
		print "\t\t-i\tApp Enumerate Intents"
		print "\t\t-l\tApp Enumerate Libraries"
		print "\t\t-m\tApp Enumerate Metadata"
		print "\t\t-p\tApp Enumerate Permissions"
		print "\t\t-q\tApp Enumerate Dangerous Permissions"
		print "\t\t-s\tApp Enumerate Services"
		print "\t\t-sc\tApp Enumerate Secret Codes"
		print "\t\t-sc\tApp Enumerate Strings"
		print "\t\t-t\tApp Enumerate Source code Strings"
		print "\t\t-x\tApp Enumerate Everything\n"
		sys.exit()
	
			
def filter_permissions(outputraw):
	output=[]
	insecureperm = ['ACCOUNT_MANAGER','AUTHENTICATE_ACCOUNTS','BIND_DEVICE_ADMIN','GET_ACCOUNTS','MANAGE_ACCOUNTS','MANAGE_APP_TOKENS','USE_CREDENTIALS','WRITE_SECURE_SETTINGS','WRITE_SETTINGS','WRITE_SYNC_SETTINGS','ACCESS_COARSE_LOCATION','ACCESS_FINE_LOCATION','LOCATION_HARDWARE','BLUETOOTH_ADMIN','BLUETOOTH_PRIVILEGED','INTERNET','NFC','TRANSMIT_IR','WRITE_APN_SETTINGS','CALL_PHONE','CALL_PRIVILEGED','SEND_SMS','USE_SIP','CAPTURE_AUDIO_OUTPUT','CAPTURE_SECURE_VIDEO_OUTPUT','CAPTURE_VIDEO_OUTPUT','DUMP','PROCESS_OUTGOING_CALLS','READ_CALL_LOG','READ_CONTACTS','READ_HISTORY_BOOKMARKS','READ_LOGS','READ_SMS','RECEIVE_MMS','RECEIVE_SMS','RECEIVE_WAP_PUSH','RECORD_AUDIO','WRITE_CALL_LOG','WRITE_CONTACTS','WRITE_HISTORY_BOOKMARKS','INJECT_EVENTS','INSTALL_PACKAGES','READ_PHONE_STATE']
	for line in outputraw:
		if any ( perm in line for perm in insecureperm):
			output.append(line)
	return output

				
def parse_manifest (manifest):
	uses_feature = [] #hardware
	uses_permission = [] # app permissions
	activity = []
	uses_library = []
	service = []
	receiver = []
	provider = []	
	meta_data = []
	intent_filter = []
	permissions=[]
	data = []
	flag=""
	parent=""
	
	for line in manifest.splitlines():
		if flag == "data" and "A: android" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
			except:
				(t1,line2) = re.split('=',line)
			data.append("Data | " + parent + " | " + line2)
		if flag == "data" and "A: android" not in line:
			flag=parent			
		if "E: uses-feature" in line:
			flag = "feature"
		elif "E: uses-permission" in line:
			flag = "permission"
		elif "E: permission" in line:
			flag = "permission"
		elif "android.permission" in line:
			flag = "permission"
		elif "E: activity" in line:
			flag = "activity"
		elif "E: uses-library" in line:
			flag = "library"
		elif "E: service" in line:
			flag = "service"
		elif "E: receiver" in line:
			flag = "receiver"
		elif "E: provider" in line:
			flag = "provider"
		elif "E: meta-data" in line:
			flag = "meta-data"
		elif "E: action" in line:
			parent = flag
			flag = "intent_filter"
		elif "E: category" in line:
			parent = flag
			flag = "category"
		elif "E: data" in line:
			parent = flag
			flag = "data"
		if "A: android:name" in line:
			(t1,line2,t2,t3,t4) = re.split('"',line)
			if flag == "feature":
				uses_feature.append(line2)
				flag = ""
			elif flag == "permission":
				uses_permission.append(line2)
				flag = ""
			elif flag == "activity":
				activity.append(line2)
				flag = line2
			elif flag == "library":
				uses_library.append(line2)
				flag = line2
			elif flag == "service":
				service.append(line2)
				flag = line2
			elif flag == "receiver":
				receiver.append(line2)
				flag = line2
			elif flag == "provider":
				provider.append(line2)
				flag = line2
			elif flag == "meta-data":
				meta_data.append(line2)
				flag = "meta-data2"
			elif flag == "intent_filter" :
				intent_filter.append("Action | " + parent + " | "+line2)
				flag = parent
			elif flag == "category" :
				intent_filter.append("Category | " + parent + " | "+line2)
				flag = parent
		elif "A: android:value" in line or "A: android:resource" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
			except:
				(t1,line2) = re.split('=',line)
			if flag == "meta-data2":
				meta_data.append(line2)
				flag = line2
		elif "A: android:permission(" in line:
			try:
				(t1,line2,t2,t3,t4) = re.split('"',line)
			except:
				print line
			permissions.append("Special Permission | " + parent + " | "+line2)
			flag = parent
			
	uses_feature = list(set(uses_feature))
	uses_permission = list(set(uses_permission))
	activity = list(set(activity))
	uses_library = list(set(uses_library))
	service = list(set(service))
	receiver = list(set(receiver))
	provider = list(set(provider))
	intent_filter = list(set(intent_filter))
	permissions  = list(set(permissions))
	
	return uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data
	
	
def printlists(list):
	if list != []:
		for line in list:
			try:
				(t1,t2,line2) = re.split(' \| ',line)
				print line2
			except:
				print line
	else:
		print "N/A"
				
def printwparents(list, newlist):
	if list != []:
		for line in list:
			print line
			for line2 in newlist:
				if "| " + line + " |" in line2:
					(line3,t1,line4) = re.split('\|',line2)
					print "\t" + line3 + ">" + line4
	else:
		print "N/A"


def printwparents_sc(list, intent_filter, data, app):
	isc = 0
	if list != []:
		for line in intent_filter:
			if "SECRET_CODE" in line:
				isc = 1
				(line3,act,line4) = re.split('\|',line)
				print ('\nAndroid Secret codes \n========')
				print act
				print "\t" + line3 + ">" + line4
				for dataline in data:
					if act in dataline:
						(line3,act,line4) = re.split('\|',dataline)
						print "\t" + line3 + ">" + line4


def apps_enumeration (manifest, app, action):
	output = []
	outputraw=[]
	(uses_feature, uses_permission, activity, uses_library, service, receiver, provider, meta_data, intent_filter, permissions , data)=parse_manifest(manifest)
	newlist=permissions + intent_filter + data
	if action == "-a":
		print ('\nActivities \n========')
		printlists (activity)
	elif action == "-b":
		print ('\nBroadcast Receivers \n========')
		printlists (receiver)
	elif action == "-s":
		print ('\nServices \n========')
		printlists (service)
	elif action == "-d":
		print ('\nData \n========')
		printlists (data)
	elif action == "-c":
		temp = subprocess.check_output('unzip -p ' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		if temp != "":
			print ('\nContent Providers \n========\n' + temp)
	elif action == "-e":
		temp = subprocess.check_output('unzip -p ' + app + ' | strings | grep "\.db.\?$" | sed -e "s/\t//"', shell=True)
		if temp != "":
			print ('\nDatabases \n========\n' + temp)
	elif action == "-p":
		print ('\nPermissions \n========')
		printlists (uses_permission)
	elif action == "-i":
		print ('\nActions \n========')
		printlists (intent_filter)
	elif action == "-f":
		print ('\nFeatures \n========')
		printlists (uses_feature)
	elif action == "-l":
		print ('\nLibraries \n========')
		printlists (uses_library)
	elif action == "-m":
		print ('\nMeta-Data \n========')
		printlists (meta_data)
	elif action == "-sc":
		printwparents_sc (activity, intent_filter, data, app) 
	elif action == "-x":
		print ('\nActivities \n========')
		printwparents (activity, newlist)
		print ('\nBroadcast Receivers \n========')
		printwparents (receiver, newlist)
		print ('\nServices \n========')
		printwparents (service, newlist)
		temp = subprocess.check_output('unzip -p ' + app + ' | strings | egrep "content://[a-zA-Z]" | sed -e "s/.*content:/content:/"', shell=True)
		print ('\nContent Providers \n========\n' + temp)
		print ('\nPermissions \n========')
		printwparents (uses_permission, newlist)
		print ('\nFeatures \n========')
		printwparents (uses_feature, newlist)
		print ('\nLibraries \n========')
		printwparents (uses_library, newlist)
		print ('\nMeta-Data \n========')
		printlists (meta_data)
		print ('\nSource Code Strings \n===================')
		extract_text(app)
	elif action == "-q":
		temp = uses_permission + permissions
		output = filter_permissions(temp)
		print ('\nDangerous Permissions \n========')
		printlists(output)
	elif action == "-t":
		print ('\nSource Code Strings \n===================')
		extract_text(app)


def extract_text(app):
	strings = ["key", "pass", "code", "user", "token","http://","https://"]
	strings2 = ["getSharedPreferences()","MODE_PRIVATE","MODE_WORLD_READABLE","MODE_WORD_WRITEABLE","addPreferencesFormResource","getExternalStorageDirectory()sdcard","db","sqlite","database","insert","delete","select","table","cursor","rawQueryin","IDENTIFICADORES","uid","user-id","imei","deviceId","deviceSerialNumber","devicePrint","X-DSN","phone","mdn","did","IMSI","uuid","HASHES","MD5","BASE64","des","getLastKnownLocation()","requestLocationUpdates()","getLatitude()","getLongitude()","LOCATION","http","https","HttpURLConnection","URLConnection","URL","TrustAllSSLSocket-Factory","AllTrustSSLSocketFactory","NonValidatingSSLSocketFactory","Toast.makeText","LOG"]
	#temp = subprocess.check_output('unzip ' + app + ' classes.dex ; java -jar baksmali-2.1.0.jar classes.dex', shell=True)
	for item in strings:
		#temp = subprocess.check_output('find ./out -name "*.smali" -exec fgrep ' + item + ' {} \;', shell=True)
		temp = subprocess.check_output('unzip -p '+ app +' classes.dex | strings | grep ' + item, shell=True)
		print temp

	
def getmanifest(app):
	try:
		act = subprocess.check_output( Path_aapt + ' dump xmltree ' + app + ' AndroidManifest.xml' , shell=True)
		'''
		manifest = subprocess.check_output(' unzip -p ' + app + ' AndroidManifest.xml' , shell=True)
		ap = dvm.AXMLPrinter(manifest)
		print ap.getBuff()
		http://androguard.blogspot.com/2011/03/androids-binary-xml.html
		'''
		return act
	except:
		print "Invalid App"
		usage()
	
	
if __name__ == "__main__":
	actionslist = ["-a","-b","-c","-d","-e","-f","-i","-l","-m","-p","-q","-s","-sc","-t","-x"]
	signal.signal(signal.SIGINT, signal_handler)
	if (len(sys.argv) != 3):
		usage()
	action=sys.argv[1].lower()
	if action not in actionslist:
		usage()
	app=sys.argv[2]
	if (action in actionslist) and (app != ""):
		manifest = getmanifest(app)
		apps_enumeration(manifest, app, action)
	else:
		print "\nError - Unknown Option" 
		usage()			

