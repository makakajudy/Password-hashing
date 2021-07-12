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


user_name = input("enter user name: ")
user_passwd = input("user enter a password: ")
# #saved_password = hashing(user_passwd)
# #
# write_file = open("mypw.txt", 'a')
# write_file.write("\n" + user_name + "," + user_passwd)
# write_file.close()

read_file = open("mypw.txt", 'r')
for line in read_file:
    user, pw = line.split(",")
    pw = pw.strip()
    #print(pw,user)
    if user==user_name and pw==user_passwd:
        print("success")
        break











read_file.close()

# x = " a,b"
# g, h = (x.split(","))
# print(x)
# #print(g, h)
# h = h.strip()
# print(g, h)

# print(password_authenticating(saved_password, "lise"))
# print(password_authenticating(saved_password,userpassword))
