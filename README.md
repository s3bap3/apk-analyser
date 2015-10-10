# apk-analyser
The APK Static Analyzer is a tool to analyze Android APK in an static way. This script will extract information from the application's manifest and source code, and display it in a fashion way (except the strings from the source code).

Android AAPT tool is required so far in order to extract the information from the Android manifest

	Usage:
		apk-analyser.py -{a,b,c,d,f i,l,m,p,q,s,u,x} {App}
		-a	App Enumerate Activities
		-b	App Enumerate Broadcast Receiver
		-c	App Enumerate Content Providers
		-d	App Enumerate Data
		-e	App Enumerate Databases
		-f	App Enumerate Features
		-i	App Enumerate Intents
		-l	App Enumerate Libraries
		-m	App Enumerate Metadata
		-p	App Enumerate Permissions
		-q	App Enumerate Dangerous Permissions
		-s	App Enumerate Services
		-sc	App Enumerate Secret Codes
		-sc	App Enumerate Strings
		-t	App Enumerate Source code Strings
		-x	App Enumerate Everything
