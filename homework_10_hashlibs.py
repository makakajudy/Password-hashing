import binascii
import hashlib
import os

"""
objective of this program

create program that prompts the user to login or register
store these details in a file in there hashed format
if new reg the user details are added to the file and they are prompted to login
if user enter wrong password the warned """


def hashing(a_password):
    # generate a salt

    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    # print(salt) # b'xxx'
    hashed_password = hashlib.pbkdf2_hmac('sha512', a_password.encode('utf8'), salt, 100000)
    # print(hashing_pw)# out is in b'\xbb\x9b\x16\' format not matching the salt
    hashed_password = binascii.hexlify(hashed_password)  # hexlify() covert  data to hexadecimal representation b'xxx'
    # print(hashing_pw)
    # combine the salt and the password(hashing_pw)to make it difficult to crack and increase the scale of searching
    return (salt + hashed_password).decode("ascii")


def password_authenticating(db_password, user_password):
    # verifying if the user password is correct by comparing their hash values
    # separate the salt and the hashed_password,saved_password=salt+hashed_password

    salt = db_password[:64]  # the first 64 bytes are occupied by the salt

    db_password = db_password[64:]  # the rest from pos 64 to end are occupied by the actual password

    hashed_password = hashlib.pbkdf2_hmac('sha512', user_password.encode('utf8'), salt.encode('ascii'), 100000)
    hashed_password = binascii.hexlify(hashed_password).decode("ascii")
    return hashed_password == db_password


def admin_only():  # for higher level admin use.used to reset password incase a user has forgotten
    read_file = open("admin.txt", 'r')
    for i in read_file:
        print(i, end='')
    read_file.close()


def creating_pw(user_name, user_passwd):  # for a higher level admin use.to add new admin passwords
    write_file = open("judy.txt", 'a')
    write_file.write("\n" + user_name + "," + hashing(user_passwd))
    write_file.close()


def use_login(user_name, user_passwd):
    my_dict = {}
    read_file = open("judy.txt", 'r')
    for line in read_file.readlines():
        user, pw = line.split(",")
        pw = pw.strip()
        my_dict.update({user: pw})
    # key_check(user_name, my_dict)# to check entered user name is in the dict
    # print(my_dict)
    i = 0
    saved_password = my_dict[user_name]
    access = False
    while i < len(my_dict) and access != True:
        for x, y in my_dict.items():
            if x == user_name and saved_password:
                if password_authenticating(saved_password, user_passwd):
                    print("\u001b[32m access granted\u001b[0m")
                    access = True
                    break
        i += 1
    if access == False:
        print("\u001b[31maccess denied\u001b[0m")
    read_file.close()


def key_check(user_name, my_dict):
    if user_name not in my_dict:
        return "invalid user name"


def instruction():
    return """\u001b[35mThis program demonstrates the use of hashlib using bkdf2_hmac and other SHA.via hashing() and password_authenticating().
    How it works:
    There is already a file with saved logging credentials in the judy.txt with passwords already hashed.
    There is also another file with unhashed passwords so that it human readable only to be used
    when unsure of your password.
    This program does not cater for unknown username yet.\u001b[0m
    
     
     \u001b[32m***** Please use SAVED USERNAMES ONLY to test**** \u001b[0m"""


admin_only() #uncomment and only use first time to see saved password
hint: print(chr(27) + "[2J") 
print()
print(instruction())
print()
print("ADMIN LOGINS")
print()
print("\u001b[32mplease enter the below credentials to login\u001b[0m")

username = input("enter user name: ")
password = input("user enter a password: ")
use_login(username, password)
