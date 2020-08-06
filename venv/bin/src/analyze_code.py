# **************************************************************************
# Created on 24-Oct-2018 by Aniruddha Ghosh
# Maintained at https://github.com/aniruddha-stqc/ios_script
# **************************************************************************
import os
import globals
import datetime
import re
#**************************************************************************
#Hard coding search case insensitively in all files
#**************************************************************************
def search_hardcode(text_to_find, file_to_write):
    globals.write_to_file("\nResults for: " + text_to_find + "\n", file_to_write)
    for root, dirs, files in os.walk(globals.gv_path_to_code_folder):
        for file in files:
            if file.endswith(".swift") or file.endswith(".c") or file.endswith(".plist"):
                try:
                    lv_searchfile = open(os.path.join(root, file), 'r')
                    # read the contents of the file
                    with lv_searchfile as searchfile:
                    #read one line at a time
                        for line_num, line_text in enumerate(searchfile):
                            #Case insensitive search for the text
                            if re.search(text_to_find, line_text, re.IGNORECASE):
                                #Create relative path
                                lv_filename = os.path.relpath ( os.path.join(root, file), globals.gv_path_to_base)
                                #Write results to the log
                                globals.write_to_file( lv_filename + ":" + str(line_num) + "  " + line_text, file_to_write)
                except:
                    lv_filename = os.path.relpath(os.path.join(root, file), globals.gv_path_to_base)
                    globals.write_to_file("Error analyzing file: " + lv_filename + "\n", globals.gv_path_to_error_file)

#**************************************************************************
#Generic Search Function to find strings in files as per following:
#Print the file name, line number, and line for each match.
#**************************************************************************
def search_generic(file_type_to_search, text_to_find, file_to_write):
    globals.write_to_file("\nResults for: " + text_to_find + "\n", file_to_write)
    for root, dirs, files in os.walk(globals.gv_path_to_code_folder):
        for file in files:
            #Search in the JAVA/xml/gradle files
            if file.endswith(file_type_to_search):
                try:
                    lv_searchfile = open(os.path.join(root, file), 'r')
                    #read the contents of the file
                    with lv_searchfile as searchfile:
                        #read one line at a time
                        for line_num, line_text in enumerate(searchfile):
                            #Case insensitive search for the text
                            if re.search(text_to_find, line_text):
                                #Create relative path
                                lv_filename = os.path.relpath ( os.path.join(root, file), globals.gv_path_to_base)
                                #Write results to the log
                                globals.write_to_file( lv_filename + ":" + str(line_num) + "  " + line_text, file_to_write)
                except:
                    lv_filename = os.path.relpath(os.path.join(root, file), globals.gv_path_to_base)
                    globals.write_to_file("Error analyzing file: " + lv_filename + "\n", globals.gv_path_to_error_file)
#**************************************************************************
#OWASP MASVS v1.0 point 2.1
#Cheat Sheet:
#Testing Local Data Storage (MSTG-STORAGE-1 and MSTG-STORAGE-2)
#**************************************************************************
def search_storage():
    globals.write_to_file("START OF: Execution log for V2.1\n", "logs/log_STORAGE-1.txt")
    search_generic(".swift","NSFileProtectionComplete", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","NSFileProtectionCompleteUnlessOpen", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","NSFileProtectionCompleteUntilFirstUserAuthentication", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","NSFileProtectionNone", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessGroup", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","securityd", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","SecItemAdd", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","SecItemAdd", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","SecItemCopyMatching", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","SecItemDelete", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleAlways", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleAlwaysThisDeviceOnly", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleAfterFirstUnlock", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleWhenUnlocked", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleWhenUnlockedThisDeviceOnly", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAccessControlDevicePasscode", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAccessControlBiometryAny", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAccessControlUserPresence", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAccessControlBiometryCurrentSet", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrKeyType", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", 'logs/log_STORAGE-1.txt')
    search_generic(".swift","LAContext", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "UserDefaults", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSUserDefaults", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "AccessControlFlags", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "kSecAttrTokenID", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "kSecAttrTokenIDSecureEnclave", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "kSecAttrIsPermanent", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "kSecPublicKeyAttrs", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "kSecPrivateKeyAttrs", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "CFDictionary", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "SecKeyGeneratePair", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSMutableData", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSDataWritingWithoutOverwriting", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSDataWritingFileProtectionNone", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSDataWritingFileProtectionComplete", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSDataWritingFileProtectionCompleteUnlessOpen", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "writeToFile", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSSearchPathForDirectoriesInDomains", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSTemporaryDirectory", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSFileManager", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "createFileAtPath", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "NSFetchedResultsController", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "firebaseio", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "Realm", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "CouchbaseLite", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "CouchbaseLiteSwift", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "YapDatabase", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "CouchbaseLite", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "keychain", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "CouchbaseLite", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "sqlite", 'logs/log_STORAGE-1.txt')
    search_generic(".swift", "Cache", 'logs/log_STORAGE-1.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.1\n", "logs/log_STORAGE-1.txt")
    print("Completed MSTG-STORAGE-1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.2
#Cheat Sheet:
#Checking Logs for Sensitive Data (MSTG-STORAGE-3)
#**************************************************************************
def search_logging():
    globals.write_to_file("START OF: Execution log for V2.2\n", "logs/log_STORAGE-3.txt")
    search_generic(".swift","NSLog", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "printf", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "NSAssert", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "Macro", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "NSCAssert", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "fprintf", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "Logging", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "Logfile", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "NSCAssert", 'logs/log_STORAGE-3.txt')
    search_generic(".swift", "DEBUG", 'logs/log_STORAGE-3.txt')
    search_generic(".pch", "ifdef", 'logs/log_STORAGE-3.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.2\n", "logs/log_STORAGE-3.txt")
    print("Completed MSTG-STORAGE-3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")
#**************************************************************************
#OWASP MASVS v1.0 point 2.3
#Cheat Sheet:
#Whether Sensitive Data Is Sent to Third Parties (MSTG-STORAGE-4)
#**************************************************************************
def search_logging():
    globals.write_to_file("START OF: Execution log for V2.3\n", "logs/log_STORAGE-4.txt")
    search_hardcode("pod", 'logs/log_STORAGE-4.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.3\n", "logs/log_STORAGE-4.txt")
    print("Completed MSTG-STORAGE-4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.4
#Cheat Sheet:
#Finding Sensitive Data in the Keyboard Cache (MSTG-STORAGE-5)
#**************************************************************************
def search_keyboard_cache():
    globals.write_to_file("START OF: Execution log for V2.4\n", "logs/log_STORAGE-5.txt")
    search_generic(".swift","autocorrectionType", 'logs/log_STORAGE-5.txt')
    search_generic(".swift", "secureTextEntry", 'logs/log_STORAGE-5.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.4\n", "logs/log_STORAGE-5.txt")
    print("Completed MSTG-STORAGE-5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.5
#Cheat Sheet:
#Whether Sensitive Data Is Exposed via IPC Mechanisms (MSTG-STORAGE-6)
#**************************************************************************
def search_clipboard():
    globals.write_to_file("START OF: Execution log for V2.5\n", "logs/log_STORAGE-6.txt")
    globals.write_to_file("IMPORTANT: Best tested on Real Device\n", "logs/log_STORAGE-6.txt")
    search_generic(".swift", "NSXPCConnection", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSXPCInterface", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSXPCListener", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSXPCListenerEndpoint", 'logs/log_STORAGE-6.txt')
    search_hardcode( "xpc.h", 'logs/log_STORAGE-6.txt')
    search_hardcode( "connection.h", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "mach_port_t", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "mach_msg_", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "CFMachPort", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "CFMessagePort", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSMachPort", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSMessagePort", 'logs/log_STORAGE-6.txt')
    search_generic(".swift", "NSFileCoordinator", 'logs/log_STORAGE-6.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.5\n", "logs/log_STORAGE-6.txt")
    print("Completed MSTG-STORAGE-6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 2.7
#Cheat Sheet:
#Sensitive Data Disclosed Through the User Interface (MSTG-STORAGE-7)
#**************************************************************************
def search_masking():
    globals.write_to_file("START OF: Execution log for V2.7\n", "logs/log_STORAGE-7.txt")
    globals.write_to_file("IMPORTANT: Best tested on Real Device\n", "logs/log_STORAGE-7.txt")
    search_generic(".swift","isSecureTextEntry", 'logs/log_STORAGE-7.txt')

    globals.write_to_file("\nEND OF: Execution log for V2.7\n", "logs/log_STORAGE-7.txt")
    print("Completed MSTG-STORAGE-7 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.1
#Cheat Sheet:
#CRYPTO-1
#**************************************************************************
def search_hardcode_keys():
    globals.write_to_file("START OF: Execution log for V3.1\n", "logs/log_CRYPTO-1.txt")
    search_hardcode("confidential", 'logs/log_CRYPTO-1.txt')
    search_hardcode("key", 'logs/log_CRYPTO-1.txt')
    search_hardcode("password", 'logs/log_CRYPTO-1.txt')
    search_hardcode("passphrase", 'logs/log_CRYPTO-1.txt')
    search_hardcode("Token", 'logs/log_CRYPTO-1.txt')
    search_hardcode("final", 'logs/log_CRYPTO-1.txt')
    search_hardcode("enum", 'logs/log_CRYPTO-1.txt')
    search_hardcode("AUTHTOKEN", 'logs/log_CRYPTO-1.txt')
    search_hardcode("SecretKeySpec", 'logs/log_CRYPTO-1.txt')
    search_hardcode("AES", 'logs/log_CRYPTO-1.txt')
    search_hardcode("IvParameterSpec", 'logs/log_CRYPTO-1.txt')
    search_hardcode("cipher.init", 'logs/log_CRYPTO-1.txt')
    globals.write_to_file("\nEND OF: Execution log for V3.1\n", "logs/log_CRYPTO-1.txt")
    print("Completed MSTG-CRYPTO-1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.2
#Cheat Sheet:
#Configuration of Cryptographic Standard Algorithms (MSTG-CRYPTO-2 and MSTG-CRYPTO-3)
#**************************************************************************
def search_algos():
    globals.write_to_file("START OF: Execution log for V3.2\n", "logs/log_CRYPTO-2.txt")
    search_generic(".swift","MD5", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift","SHA1", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift","HMAC", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift","AES", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift","public", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "private", 'logs/log_CRYPTO-2.txt')

    search_hardcode("Commoncryptor.h", 'logs/log_CRYPTO-2.txt')
    search_hardcode("CommonDigest.h", 'logs/log_CRYPTO-2.txt')
    search_hardcode( "CommonHMAC.h", 'logs/log_CRYPTO-2.txt')
    search_hardcode( "CommonKeyDerivation.h", 'logs/log_CRYPTO-2.txt')
    search_hardcode( "CommonSymmetricKeywrap.h", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "IDZSwiftCommonCrypto", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "Heimdall", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "SwiftyRSA", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "SwiftSSL", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "RNCryptor", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "Arcane", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CJOSE", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CryptoSwift", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "OpenSSL", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "LibSodium", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "Tink", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "Themis", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CocoaSecurity", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "aerogear-ios-crypto", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CommonCryptor", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CCCrypt", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CCCryptorCreate", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "Carthage", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CCCrypt", 'logs/log_CRYPTO-2.txt')
    search_generic(".swift", "CCCrypt", 'logs/log_CRYPTO-2.txt')

    globals.write_to_file("\nEND OF: Execution log for V3.2\n", "logs/log_CRYPTO-2.txt")
    print("Completed MSTG-CRYPTO-2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.3
#Cheat Sheet:
#Testing Key Management (MSTG-CRYPTO-1 and MSTG-CRYPTO-5)
#**************************************************************************
def search_old_algos():
    globals.write_to_file("START OF: Execution log for V3.3\n", "logs/log_CRYPTO-5.txt")
    search_generic(".swift","pbkdf2SHA1", 'logs/log_CRYPTO-5.txt')
    search_generic(".swift", "pbkdf2SHA256", 'logs/log_CRYPTO-5.txt')
    search_generic(".swift", "pbkdf2SHA512", 'logs/log_CRYPTO-5.txt')
    search_generic(".swift", "CCPBKDFAlgorithm", 'logs/log_CRYPTO-5.txt')
    search_generic(".swift", "kSecAttrAccessibleAlways", 'logs/log_CRYPTO-5.txt')
    search_generic(".swift", "NSUserDefaults", 'logs/log_CRYPTO-5.txt')

    globals.write_to_file("\nEND OF: Execution log for V3.3\n", "logs/log_CRYPTO-5.txt")
    print("Completed MSTG-CRYPTO-5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 3.6
#Cheat Sheet:
#Testing Random Number Generation (MSTG-CRYPTO-6)
#**************************************************************************
def search_random():
    globals.write_to_file("START OF: Execution log for V3.6\n", "logs/log_CRYPTO-6.txt")
    search_generic(".swift","SecRandomCopyBytes", 'logs/log_CRYPTO-6.txt')
    search_hardcode("Random", 'logs/log_CRYPTO-6.txt')

    globals.write_to_file("\nEND OF: Execution log for V3.6\n", "logs/log_CRYPTO-6.txt")
    print("Completed MSTG-CRYPTO-6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 4.1
#Cheat Sheet:
#Testing Authentication (MSTG-AUTH-1)
#**************************************************************************
def search_authentication():
    globals.write_to_file("START OF: Execution log for V4.1\n", "logs/log_AUTH-1.txt")
    search_generic(".swift", "PIN", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "password", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "biometric", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "keychain", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "Touch", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "LocalAuthentication", 'logs/log_AUTH-1.txt')
    search_generic(".swift", "Security.framework", 'logs/log_AUTH-1.txt')

    globals.write_to_file("\nEND OF: Execution log for V4.1\n", "logs/log_AUTH-1.txt")
    print("Completed MSTG-AUTH-1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 4.1
#Cheat Sheet:
#Testing Local Authentication (MSTG-AUTH-8)
#**************************************************************************
def search_local_authentication():
    globals.write_to_file("START OF: Execution log for V4.1\n", "logs/log_AUTH-8.txt")

    search_hardcode("deviceOwnerAuthentication", 'logs/log_AUTH-8.txt')
    search_hardcode("LAPolicyDeviceOwnerAuthentication", 'logs/log_AUTH-8.txt')
    search_hardcode("deviceOwnerAuthenticationWithBiometrics", 'logs/log_AUTH-8.txt')
    search_hardcode("LAPolicyDeviceOwnerAuthenticationWithBiometrics", 'logs/log_AUTH-8.txt')
    search_hardcode("evaluatePolicy", 'logs/log_AUTH-8.txt')
    search_hardcode("LAContext", 'logs/log_AUTH-8.txt')
    search_hardcode("SecAccessControl", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", 'logs/log_AUTH-8.txt')
    search_hardcode("SecAccessControlCreateFlags", 'logs/log_AUTH-8.txt')
    search_hardcode("SecAccessControlCreateFlags", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAccessControlTouchIDCurrentSet", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAccessControlBiometryAny", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAccessControlTouchIDAny", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAccessControlUserPresence", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAttrAccessibleWhenPasscodeSet", 'logs/log_AUTH-8.txt')
    search_hardcode("kSecAccessControlUserPresence", 'logs/log_AUTH-8.txt')

    globals.write_to_file("\nEND OF: Execution log for V4.1\n", "logs/log_AUTH-8.txt")
    print("Completed MSTG-AUTH-8 by: " + str((datetime.datetime.now() - globals.gv_time_start).total_seconds()) + " seconds")
#**************************************************************************
#OWASP MASVS v1.0 point 5.1
#Cheat Sheet:
#App Transport Security (MSTG-NETWORK-2)
#**************************************************************************
def search_transport():
    globals.write_to_file("START OF: Execution log for V5.1\n", "logs/log_v5.1.txt")
    search_hardcode("http:", 'logs/log_NETWORK-2.txt')
    search_hardcode("https:", 'logs/log_NETWORK-2.txt')
    search_hardcode("ftp:", 'logs/log_NETWORK-2.txt')
    search_hardcode("sftp:", 'logs/log_NETWORK-2.txt')
    search_generic(".swift","URLSession", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "NSURLConnection", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "NSURLConnection", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "CFURL", 'logs/log_NETWORK-2.txt')

    search_generic(".plist", "NSAppTransportSecurity", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSAllowsArbitraryLoads", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSAllowsArbitraryLoadsInWebContent", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSAllowsLocalNetworking", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSAllowsArbitraryLoadsForMedia", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSIncludesSubdomains", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSExceptionAllowsInsecureHTTPLoads", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSExceptionMinimumTLSVersion", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSExceptionRequiresForwardSecrecy", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSAllowsArbitraryLoadsInWebContent", 'logs/log_NETWORK-2.txt')
    search_generic(".plist", "NSExceptionDomains", 'logs/log_NETWORK-2.txt')

    globals.write_to_file("\nEND OF: Execution log for V5.1\n", "logs/log_NETWORK-2.txt")
    print("Completed MSTG-NETWORK-2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")
#**************************************************************************
#OWASP MASVS v1.0 point 5.3
#Cheat Sheet:
#Testing Custom Certificate Stores and Certificate Pinning (MSTG-NETWORK-3 and MSTG-NETWORK-4)
#**************************************************************************
def search_x509_validation():
    globals.write_to_file("START OF: Execution log for V5.3\n", "logs/log_NETWORK-2.txt")
    search_generic(".swift", "connection:canAuthenticateAgainstProtectionSpace", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "forAuthenticationChallenge", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "SecTrustEvaluate", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "TrustKit", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "ServerTrustPolicy", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "AFSecurityPolicy", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "AlamoFire", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "TrustKit", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "AFNetworking", 'logs/log_NETWORK-2.txt')
    search_generic(".swift", "CFStream", 'logs/log_NETWORK-2.txt')

    search_hardcode( "x509", 'logs/log_NETWORK-2.txt')

    globals.write_to_file("\nEND OF: Execution log for V5.3\n", "logs/log_NETWORK-2.txt")
    print("Completed MSTG-NETWORK-3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.1
#Cheat Sheet:
#Search for 'GPS', "PendingIntent"
#Testing App Permissions (MSTG-PLATFORM-1)
#**************************************************************************
def search_ipc_input():
    globals.write_to_file("START OF: Execution log for V6.2\n", "logs/log_PLATFORM-1.txt")
    search_generic(".swift","bluetooth", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Calendar", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Camera", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Contacts", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Health", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","HomeKit", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Location", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Microphone", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Motion", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Music", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Photos", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Reminder", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Siri", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Speech", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","Reminder", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift","TV", 'logs/log_PLATFORM-1.txt')

    search_generic(".plist", "UIRequiredDeviceCapabilities", 'logs/log_PLATFORM-1.txt')

    search_generic(".plist", "UIBackgroundModes", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "bluetooth-le", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "bluetooth-peripheral", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "bluetooth-central", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSBluetoothPeripheralUsageDescription", 'logs/log_PLATFORM-1.txt')

    search_generic(".plist", "NSFileProtectionComplete", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "Entitlements", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "mobileprovision", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSBluetoothPeripheralUsageDescription", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSLocationWhenInUseUsageDescription", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSHealthClinicalHealthRecordsShareUsageDescription", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSCameraUsageDescription", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSPhotoLibraryUsageDescription", 'logs/log_PLATFORM-1.txt')
    search_generic(".plist", "NSLocationWhenInUseUsageDescription", 'logs/log_PLATFORM-1.txt')

    search_generic(".swift", "CLLocationManager", 'logs/log_PLATFORM-1.txt')

    search_generic(".swift", "TGMediaAssetsLibrary", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift", "PHPhotoLibrary", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift", "associated-domain", 'logs/log_PLATFORM-1.txt')
    search_generic(".swift", "apple-app-site-association", 'logs/log_PLATFORM-1.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.2\n", 'logs/log_PLATFORM-1.txt')
    print("Completed MSTG-PLATFORM-1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 6.4
#Cheat Sheet:
#Testing Custom URL Schemes (MSTG-PLATFORM-3)
#**************************************************************************
def search_ipc_output():
    globals.write_to_file("START OF: Execution log for V6.4\n", "logs/log_PLATFORM-3.txt")

    search_generic(".plist", "CFBundleURLTypes", 'logs/log_PLATFORM-3.txt')
    search_generic(".plist", "CFBundleURLName", 'logs/log_PLATFORM-3.txt')
    search_generic(".plist", "CFBundleURLSchemes", 'logs/log_PLATFORM-3.txt')
    search_generic(".plist", "LSApplicationQueriesSchemes", 'logs/log_PLATFORM-3.txt')
    search_generic(".plist", "LSApplicationQueriesSchemes", 'logs/log_PLATFORM-3.txt')
    search_generic(".plist", "CFBundleURLSchemes", 'logs/log_PLATFORM-3.txt')

    search_generic(".swift", "didFinishLaunchingWithOptions", 'logs/log_PLATFORM-3.txt')
    search_generic(".swift", "application:openURL:options", 'logs/log_PLATFORM-3.txt')
    search_generic(".swift", "application:handleOpenURL:", 'logs/log_PLATFORM-3.txt')
    search_generic(".swift", "openURL:", 'logs/log_PLATFORM-3.txt')
    search_generic(".swift", "application:openURL:sourceApplication:annotation:", 'logs/log_PLATFORM-3.txt')
    search_generic(".swift", "UIApplicationOpenURLOptionsSourceApplicationKey", 'logs/log_PLATFORM-3.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.4\n", "logs/log_PLATFORM-3.txt")
    print("Completed MSTG-PLATFORM-3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 6.4
#Cheat Sheet:
#Testing for Sensitive Functionality Exposure Through IPC (MSTG-PLATFORM-4)
#**************************************************************************
def search_ipc_output():
    globals.write_to_file("START OF: Execution log for V6.4\n", "logs/log_PLATFORM-4.txt")

    search_generic(".plist", "associated-domains", 'logs/log_PLATFORM-4.txt')
    search_generic(".plist", "NSURLComponents", 'logs/log_PLATFORM-4.txt')

    search_generic(".swift", "application:continueUserActivity:restorationHandler", 'logs/log_PLATFORM-4.txt')

    search_generic(".swift", "UIApplicationOpenURLOptionUniversalLinksOnly", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "UIActivityViewController", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "excludedActivityTypes", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "application:openURL:options", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "excludedActivityTypes", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "activityItems", 'logs/log_PLATFORM-4.txt')

    search_generic(".plist", "CFBundleDocumentTypes", 'logs/log_PLATFORM-4.txt')
    search_generic(".plist", "UTImportedTypeDeclarations", 'logs/log_PLATFORM-4.txt')
    search_generic(".plist", "NSExtensionPointIdentifier", 'logs/log_PLATFORM-4.txt')
    search_generic(".plist", "NSExtensionActivationRule", 'logs/log_PLATFORM-4.txt')
    search_generic(".plist", "UTExportedTypeDeclarations", 'logs/log_PLATFORM-4.txt')

    search_generic(".swift", "application:shouldAllowExtensionPointIdentifier", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "UIPasteboard", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "generalPasteboard", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "removePasteboardWithName", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "pasteboardWithUniqueName", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "pasteboardWithName", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "setItems:options", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "UIPasteboardOptionLocalOnly", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "UIPasteboardOptionExpirationDate", 'logs/log_PLATFORM-4.txt')
    search_generic(".swift", "setItems:options", 'logs/log_PLATFORM-4.txt')

    search_generic(".plist", "NSXPCConnection", 'logs/log_PLATFORM-4.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.4\n", "logs/log_PLATFORM-4.txt")
    print("Completed MSTG-PLATFORM-4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.5
#Cheat Sheet:
#Testing iOS WebViews (MSTG-PLATFORM-5)
#**************************************************************************
def search_setJavaScriptEnabled():
    globals.write_to_file("START OF: Execution log for V6.5\n", "logs/log_PLATFORM-5.txt")
    search_generic(".swift", "UIWebView", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "WKWebView", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "SFSafariViewController", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "javaScriptEnabled", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "JavaScriptCanOpenWindowsAutomatically", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "hasOnlySecureContent", 'logs/log_PLATFORM-5.txt')
    search_generic(".swift", "WKPreferences", 'logs/log_PLATFORM-5.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.5\n", "logs/log_PLATFORM-5.txt")
    print("Completed MSTG-PLATFORM-5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.6
#Cheat Sheet:
#Testing WebView Protocol Handlers (MSTG-PLATFORM-6)
#**************************************************************************
def search_webview_config():
    globals.write_to_file("START OF: Execution log for V6.6\n", "logs/log_PLATFORM-6.txt")
    search_generic(".swift","loadHTMLString:baseURL:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift","loadData:MIMEType:textEncodingName:baseURL:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift","baseURL", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift","applewebdata:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "pathForResource:ofType:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "URLForResource:withExtension:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "init(contentsOf:encoding:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "loadFileURL:allowingReadAccessToURL:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "URLForResource:withExtension:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "allowFileAccessFromFileURLs:", 'logs/log_PLATFORM-6.txt')
    search_generic(".swift", "allowUniversalAccessFromFileURLs", 'logs/log_PLATFORM-6.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.6\n", "logs/log_PLATFORM-6.txt")
    print("Completed MSTG-PLATFORM-6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.7
#Cheat Sheet:
#Determining Whether Native Methods Are Exposed Through WebViews (MSTG-PLATFORM-7)
#**************************************************************************
def search_addjavascriptinterface():
    globals.write_to_file("START OF: Execution log for V6.7\n", "logs/log_PLATFORM-7.txt")
    search_generic(".swift","JSContext", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "JSExport", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "valueForKeyPath", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "add(_ scriptMessageHandler:name:)", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "WKScriptMessageHandler", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "JavaScriptBridgeMessageHandler", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "JavaScriptBridgeMessageHandler", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "JavaScriptBridgeMessageHandler", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "evaluateJavaScript:completionHandler:", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "stringByEvaluatingJavaScriptFromString:", 'logs/log_PLATFORM-7.txt')
    search_generic(".swift", "javascriptBridgeCallBack:", 'logs/log_PLATFORM-7.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.7\n", "logs/log_PLATFORM-7.txt")
    print("Completed MSTG-PLATFORM-7 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 6.8
#Cheat Sheet:
#Testing Object Persistence (MSTG-PLATFORM-8)
#**************************************************************************
def search_serialization():
    globals.write_to_file("START OF: Execution log for V6.8\n", "logs/log_PLATFORM-8.txt")
    search_generic(".swift","NSCoding", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift","NSSecureCoding", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "NSMutableData", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "NSCoding", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "NSKeyedArchiver", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Codable", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "NSKeyedUnarchiver", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "JSONEncoder", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Mantle", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "JSONModel", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "JSONEncoder", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "SwiftyJSON", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "ObjectMapper", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "JSONKit", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "YYModel", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "SBJson", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Unbox", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Gloss", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Mapper", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "JASON", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Arrow", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Fuzi", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Ono", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "AEXML", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "Mapper", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "RaptureXML", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "SwiftyXMLParser", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "SWXMLHash", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "XMLParser", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "shouldResolveExternalEntities", 'logs/log_PLATFORM-8.txt')
    search_generic(".swift", "protobuf", 'logs/log_PLATFORM-8.txt')

    globals.write_to_file("\nEND OF: Execution log for V6.8\n", "logs/log_PLATFORM-8.txt")
    print("Completed MSTG-PLATFORM-8 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.4
#Cheat Sheet:
#Finding Debugging Code and Verbose Error Logging (MSTG-CODE-4)
#**************************************************************************
def search_debugging_code():
    globals.write_to_file("START OF: Execution log for V7.4\n", "logs/log_CODE-4.txt")
    search_generic(".swift","debug", 'logs/log_CODE-4.txt')
    search_generic(".swift","proxy", 'logs/log_CODE-4.txt')
    search_generic(".swift","test", 'logs/log_CODE-4.txt')
    search_generic(".swift","uat", 'logs/log_CODE-4.txt')
    search_generic(".swift","demo", 'logs/log_CODE-4.txt')
    search_generic(".swift", "NSLog", 'logs/log_CODE-4.txt')
    search_generic(".swift", "println", 'logs/log_CODE-4.txt')
    search_generic(".swift", "print", 'logs/log_CODE-4.txt')
    search_generic(".swift", "dump", 'logs/log_CODE-4.txt')
    search_generic(".swift", "debugPrint", 'logs/log_CODE-4.txt')
    search_generic(".swift", "_isDebugAssertConfiguration", 'logs/log_CODE-4.txt')
    search_generic(".swift", "_isReleaseAssertConfiguration", 'logs/log_CODE-4.txt')
    search_generic(".swift", "_isFastAssertConfiguration", 'logs/log_CODE-4.txt')
    search_generic(".swift", "debugPrint", 'logs/log_CODE-4.txt')

    globals.write_to_file("\nEND OF: Execution log for V7.4\n", "logs/log_CODE-4.txt")
    print("Completed MSTG-CODE-4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.9
#Cheat Sheet:
#Weaknesses in Third Party Libraries (MSTG-CODE-5)
#**************************************************************************
def search_gradle():
    globals.write_to_file("START OF: Execution log for V7.9\n", "logs/log_CODE-5.txt")
    search_hardcode("carthage", 'logs/log_CODE-5.txt')
    search_hardcode("cocoa", 'logs/log_CODE-5.txt')
    globals.write_to_file("\nEND OF: Execution log for V7.9\n", "logs/log_CODE-5.txt")
    print("Completed MSTG-CODE-5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.9
#Cheat Sheet:
#Testing Exception Handling (MSTG-CODE-6)
#**************************************************************************
def search_gradle():
    globals.write_to_file("START OF: Execution log for V7.9\n", "logs/log_CODE-6.txt")
    search_generic(".swift", "NSException", 'logs/log_CODE-6.txt')
    search_generic(".swift", "NSError", 'logs/log_CODE-6.txt')
    search_generic(".swift", "@catch", 'logs/log_CODE-6.txt')
    search_generic(".swift", "@finally", 'logs/log_CODE-6.txt')
    search_generic(".swift", "@try", 'logs/log_CODE-6.txt')
    search_generic(".swift", "@throw", 'logs/log_CODE-6.txt')
    search_generic(".swift", "raise", 'logs/log_CODE-6.txt')
    search_generic(".swift", "defer", 'logs/log_CODE-6.txt')
    search_generic(".swift", "NSSetUncaughtExceptionHandler", 'logs/log_CODE-6.txt')

    globals.write_to_file("\nEND OF: Execution log for V7.9\n", "logs/log_CODE-6.txt")
    print("Completed MSTG-CODE-6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.9
#Cheat Sheet:
#Testing Exception Handling (MSTG-CODE-8)
#**************************************************************************
def search_gradle():
    globals.write_to_file("START OF: Execution log for V7.9\n", "logs/log_CODE-8.txt")
    search_generic(".swift", "free", 'logs/log_CODE-8.txt')
    search_generic(".swift", "UnsafePointer", 'logs/log_CODE-8.txt')
    search_generic(".swift", "Unmanaged", 'logs/log_CODE-8.txt')
    search_generic(".swift", "NSAutoreleaseFreedObjectCheckEnabled", 'logs/log_CODE-8.txt')
    search_generic(".swift", "NSZombieEnabled", 'logs/log_CODE-8.txt')
    search_generic(".swift", "NSDebugEnabled", 'logs/log_CODE-8.txt')

    globals.write_to_file("\nEND OF: Execution log for V7.9\n", "logs/log_CODE-8.txt")
    print("Completed MSTG-CODE-8 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 7.9
#Cheat Sheet:
#Make Sure That Free Security Features Are Activated (MSTG-CODE-9)
#**************************************************************************
def search_gradle():
    globals.write_to_file("START OF: Execution log for V7.9\n", "logs/log_CODE-9.txt")
    globals.write_to_file("\nNeeds signed IPA file and Xcode Project Settings\n", "logs/log_CODE-9.txt")

    globals.write_to_file("\nEND OF: Execution log for V7.9\n", "logs/log_CODE-9.txt")
    print("Completed MSTG-CODE-9 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.1
#Cheat Sheet:
#Jailbreak Detection (MSTG-RESILIENCE-1)
#**************************************************************************
def search_root_detect():
    globals.write_to_file("START OF: Execution log for V8.1\n", "logs/log_RESILIENCE-1.txt")

    search_hardcode("Cydia", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("IntelliScreen", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("MxTube", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("RockApp", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("SBSettings", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("WinterBoard", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("blackra1n", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("LiveClock", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("Veency", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("MobileSubstrate", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("com.ikey.bbot.plist", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("com.saurik.Cydia.Startup.plist", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/bin/bash", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("Veency", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/bin/sh", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/etc/apt", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/etc/ssh/sshd_config", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/private/var/lib/apt", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/private/var/lib/cydia", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/private/var/mobile/Library/SBSettings/Themes", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/private/var/stash", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/private/var/tmp/cydia.log", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/var/tmp/cydia.log", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("usr/bin/sshd", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/libexec/sftp-server", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/libexec/ssh-keysign", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/sbin/sshd", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/var/cache/apt", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/var/lib/cydia", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/bin/cycript", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/local/bin/cycript", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/usr/lib/libcycript.dylib", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("/var/log/syslog", 'logs/log_RESILIENCE-1.txt')
    search_hardcode("SFAntiPiracy", 'logs/log_RESILIENCE-1.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.1\n", "logs/log_RESILIENCE-1.txt")
    print("Completed MSTG-RESILIENCE-1 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.2
#Cheat Sheet:
#Testing Anti-Debugging Detection (MSTG-RESILIENCE-2)
#**************************************************************************
def search_anti_debug():
    globals.write_to_file("START OF: Execution log for V8.2\n", "logs/log_RESILIENCE-2.txt")
    search_hardcode("ptrace", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("PT_DENY_ATTACH", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("dlsym", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("dlfcn", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("sysctl", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("info.kp_proc.p_flag", 'logs/log_RESILIENCE-2.txt')
    search_hardcode("getppid", 'logs/log_RESILIENCE-2.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.2\n", "logs/log_RESILIENCE-2.txt")
    print("Completed MSTG-RESILIENCE-2 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


# **************************************************************************
# OWASP MASVS v1.0 point 8.2
# Cheat Sheet:
# File Integrity Checks (MSTG-RESILIENCE-3 and MSTG-RESILIENCE-11)
# **************************************************************************
def search_anti_debug():
    globals.write_to_file("START OF: Execution log for V8.2\n", "logs/log_RESILIENCE-3.txt")
    search_hardcode("mach_header", 'logs/log_RESILIENCE-3.txt')
    search_hardcode("NSMutableData", 'logs/log_RESILIENCE-3.txt')
    search_hardcode("HMAC", 'logs/log_RESILIENCE-3.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.2\n", "logs/log_RESILIENCE-3.txt")
    print("Completed MSTG-RESILIENCE-3 by: " + str((datetime.datetime.now() - globals.gv_time_start).total_seconds()) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.3
#Cheat Sheet:
#Reverse Engineering Tools Detection (MSTG-RESILIENCE-4)
#**************************************************************************
def search_integrity_check():
    globals.write_to_file("START OF: Execution log for V8.3\n", "logs/log_v8.3.txt")
    search_generic(".java","getPackageCodePath", 'logs/log_v8.3.txt')
    search_generic(".java","dex_crc", 'logs/log_v8.3.txt')
    search_generic(".java","ZipFile", 'logs/log_v8.3.txt')
    search_generic(".java","ZipEntry", 'logs/log_v8.3.txt')
    search_generic(".java","getCrc", 'logs/log_v8.3.txt')
    search_generic(".java","hmac", 'logs/log_v8.3.txt')
    search_generic(".java","BouncyCastle", 'logs/log_v8.3.txt')
    search_generic(".java","SpongyCastle", 'logs/log_v8.3.txt')
    search_generic(".java","getMacLength", 'logs/log_v8.3.txt')
    search_generic(".java","classes.dex", 'logs/log_v8.3.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.3\n", "logs/log_v8.3.txt")
    print("Completed V8.3 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.4
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Reverse Engineering Tools
#**************************************************************************
def search_reverse_tools():
    globals.write_to_file("START OF: Execution log for V8.4\n", "logs/log_v8.4.txt")
    search_hardcode("Substrate", 'logs/log_v8.4.txt')
    search_hardcode("Xposed", 'logs/log_v8.4.txt')
    search_hardcode("Frida", 'logs/log_v8.4.txt')
    
    search_generic(".java","frida-trace", 'logs/log_v8.4.txt')
    search_generic(".java","LD_PRELOAD", 'logs/log_v8.4.txt')
    search_generic(".java","DYLD_INSERT_LIBRARIES", 'logs/log_v8.4.txt')
    search_generic(".java","libgadget", 'logs/log_v8.4.txt')
    search_generic(".java","gdbserver", 'logs/log_v8.4.txt')
    search_generic(".java","LD_PRELOAD", 'logs/log_v8.4.txt')
    search_generic(".java","FridaGadget", 'logs/log_v8.4.txt')
    search_generic(".java","GET_SIGNING_CERTIFICATES", 'logs/log_v8.4.txt')
    search_generic(".java","frida-server", 'logs/log_v8.4.txt')
    search_generic(".java","frida-gadget", 'logs/log_v8.4.txt')
    search_generic(".java","frida-agent", 'logs/log_v8.4.txt')
    search_generic(".java","27042", 'logs/log_v8.4.txt')
    search_generic(".java","LIBFRIDA", 'logs/log_v8.4.txt')
    search_generic(".java","Runtime.getRuntime().exec", 'logs/log_v8.4.txt')
    search_generic(".java","/proc/self/maps", 'logs/log_v8.4.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.4\n", "logs/log_v8.4.txt")
    print("Completed V8.4 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.5
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Emulator Detection
#**************************************************************************
def search_emulator_detect():
    globals.write_to_file("START OF: Execution log for V8.5\n", "logs/log_v8.5.txt")
    search_generic(".java","build.prop", 'logs/log_v8.5.txt')
    search_generic(".java","Build.ABI", 'logs/log_v8.5.txt')
    search_generic(".java","BUILD.ABI2", 'logs/log_v8.5.txt')
    search_generic(".java","Build.BOARD", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Brand", 'logs/log_v8.5.txt')
    search_generic(".java","Build.DEVICE", 'logs/log_v8.5.txt')
    search_generic(".java","Build.FINGERPRINT", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Hardware", 'logs/log_v8.5.txt')
    search_generic(".java","Build.Host", 'logs/log_v8.5.txt')
    search_generic(".java","Build.ID", 'logs/log_v8.5.txt')
    search_generic(".java","Build.MANUFACTURER", 'logs/log_v8.5.txt')
    search_generic(".java","Build.MODEL", 'logs/log_v8.5.txt')
    search_generic(".java","Build.PRODUCT", 'logs/log_v8.5.txt')
    search_generic(".java","Build.RADIO", 'logs/log_v8.5.txt')
    search_generic(".java","Build.SERIAL", 'logs/log_v8.5.txt')
    search_generic(".java","Build.USER", 'logs/log_v8.5.txt')
    search_generic(".java","armeabi", 'logs/log_v8.5.txt')
    search_generic(".java","generic", 'logs/log_v8.5.txt')
    search_generic(".java","goldfish", 'logs/log_v8.5.txt')
    search_generic(".java","goldfish", 'logs/log_v8.5.txt')
    search_generic(".java","FRF91", 'logs/log_v8.5.txt')
    search_generic(".java","android-build", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getDeviceId", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getLine1", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkCountryIso", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkType", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getNetworkOperator", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getPhoneType", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSimCountryIso", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSimSerial", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getSubscriberId", 'logs/log_v8.5.txt')
    search_generic(".java","TelephonyManager.getVoiceMailNumber", 'logs/log_v8.5.txt')
    search_generic(".java","155552155", 'logs/log_v8.5.txt')
    search_generic(".java","89014103211118510720", 'logs/log_v8.5.txt')
    search_generic(".java","310260000000000", 'logs/log_v8.5.txt')
    search_generic(".java","15552175049", 'logs/log_v8.5.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.5\n", "logs/log_v8.5.txt")
    print("Completed V8.5 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")


#**************************************************************************
#OWASP MASVS v1.0 point 8.6
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Runtime Integrity Checks
#**************************************************************************
def search_runtime_integrity():
    globals.write_to_file("START OF: Execution log for V8.6\n", "logs/log_v8.6.txt")
    search_generic(".java","zygoteInitCallCount", 'logs/log_v8.6.txt')
    search_generic(".java","StackTraceElement", 'logs/log_v8.6.txt')
    search_generic(".java","stackTraceElement.getMethodName", 'logs/log_v8.6.txt')
    search_generic(".java","com.android.internal.os.ZygoteInit", 'logs/log_v8.6.txt')
    search_generic(".java","com.saurik.substrate.MS$2", 'logs/log_v8.6.txt')
    search_generic(".java","de.robv.android.xposed.XposedBridge", 'logs/log_v8.6.txt')
    search_generic(".java","stackTraceElement.getClassName", 'logs/log_v8.6.txt')
    search_generic(".java","handleHookedMethod", 'logs/log_v8.6.txt')
    search_generic(".java","trampoline", 'logs/log_v8.6.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.6\n", "logs/log_v8.6.txt")
    print("Completed V8.6 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.9
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Obfuscation
#**************************************************************************
def search_obfuscation():
    globals.write_to_file("START OF: Execution log for V8.9\n", "logs/log_v8.9.txt")
    search_hardcode("proguard", 'logs/log_v8.9.txt')
    search_hardcode("R8", 'logs/log_v8.9.txt')
    search_hardcode("obfuscat", 'logs/log_v8.9.txt')
    
    globals.write_to_file("\nEND OF: Execution log for V8.9\n", "logs/log_v8.9.txt")
    print("Completed V8.9 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")

#**************************************************************************
#OWASP MASVS v1.0 point 8.10
#Cheat Sheet:
#Search for "MAC", 
#Details:
#Device Binding
#**************************************************************************
def search_device_bind():
    globals.write_to_file("START OF: Execution log for V8.10\n", "logs/log_v8.10.txt")
    search_generic(".java","KeyGenParameterSpec", 'logs/log_v8.10.txt')
    search_generic(".java","KEY_ALGORITHM_RSA", 'logs/log_v8.10.txt')
    search_generic(".java","PURPOSE_DECRYPT", 'logs/log_v8.10.txt')
    search_generic(".java","DIGEST_SHA256", 'logs/log_v8.10.txt')
    search_generic(".java","DIGEST_SHA512", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPTION_PADDING_RSA_OAEP", 'logs/log_v8.10.txt')
    search_generic(".java","PURPOSE_ENCRYPT", 'logs/log_v8.10.txt')
    search_generic(".java","OAEPWithSHA", 'logs/log_v8.10.txt')
    search_generic(".java","BLOCK_MODE_GCM", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPTION_PADDING_NONE", 'logs/log_v8.10.txt')
    search_generic(".java","NoPadding", 'logs/log_v8.10.txt')
    search_generic(".java","GCM_NONCE_LENGTH", 'logs/log_v8.10.txt')
    search_generic(".java","GCM_TAG_LENGTH", 'logs/log_v8.10.txt')
    search_generic(".java","GCMParameterSpec", 'logs/log_v8.10.txt')
    search_generic(".java","updateAAD", 'logs/log_v8.10.txt')
    search_generic(".java","ENCRYPT_MODE", 'logs/log_v8.10.txt')
    search_generic(".java","DECRYPT_MODE", 'logs/log_v8.10.txt')
    search_generic(".java","Cipher.getInstance", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","AdvertisingIdClient", 'logs/log_v8.10.txt')
    search_generic(".java","AdvertisingIdClient", 'logs/log_v8.10.txt')
    search_generic(".java","FirebaseInstanceId", 'logs/log_v8.10.txt')
    search_generic(".java","SSAID", 'logs/log_v8.10.txt')
    search_generic(".java","Build.getSerial", 'logs/log_v8.10.txt')
    search_generic(".java","Build.SERIAL", 'logs/log_v8.10.txt')
    search_generic(".java","htc.camera.sensor.front_SN", 'logs/log_v8.10.txt')
    search_generic(".java","persist.service.bdroid.bdadd", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.bluetooth_address", 'logs/log_v8.10.txt')
    search_generic(".java","WifiInfo.getMacAddress", 'logs/log_v8.10.txt')
    search_generic(".java","LOCAL_MAC_ADDRESS", 'logs/log_v8.10.txt')
    search_generic(".java","TELEPHONY_SERVICE", 'logs/log_v8.10.txt')
    search_generic(".java","getInstance", 'logs/log_v8.10.txt')
    search_generic(".java","Instance", 'logs/log_v8.10.txt')
    search_generic(".java","getId", 'logs/log_v8.10.txt')
    search_generic(".java","getToken", 'logs/log_v8.10.txt')
    search_generic(".java","getDeviceId", 'logs/log_v8.10.txt')
    search_generic(".java","IDListenerService", 'logs/log_v8.10.txt')
    search_generic(".java","FirebaseInstanceId", 'logs/log_v8.10.txt')
    search_generic(".java","android.os.Build.SERIAL", 'logs/log_v8.10.txt')
    search_generic(".java","android.os.Build.getSerial", 'logs/log_v8.10.txt')
    search_generic(".java","TELEPHONY_SERVICE", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","persist.service.bdroid.bdadd", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.bluetooth_address", 'logs/log_v8.10.txt')
    search_generic(".java","WifiInfo.getMacAddress", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
    search_generic(".java","Settings.Secure.ANDROID_ID", 'logs/log_v8.10.txt')
        

    search_generic(".xml","READ_PHONE_STATE", 'logs/log_v8.10.txt')
    search_generic(".xml","LOCAL_MAC_ADDRESS", 'logs/log_v8.10.txt')

    globals.write_to_file("\nEND OF: Execution log for V8.10\n", "logs/log_v8.10.txt")
    print("Completed V8.10 by: " + str( (datetime.datetime.now() - globals.gv_time_start ).total_seconds() ) + " seconds")














    
