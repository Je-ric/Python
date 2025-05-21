import rsa

(Person1pubKey, Person1privKey ) = rsa.newkeys(1024)
(Person2pubKey, Person2privKey ) = rsa.newkeys(1024)

msg1 = input("Enter message 1: ")
ciphertext1 = rsa.encrypt(msg1.encode('utf8'), Person2pubKey)
plaintext1 = rsa.decrypt(ciphertext1, Person2privKey).decode('utf8')

msg2 = input("Enter message 2: ")
ciphertext2 = rsa.encrypt(msg2.encode('utf8'), Person1pubKey)
plaintext2 = rsa.decrypt(ciphertext2, Person1privKey).decode('utf8')

print(f'Person 1: {msg1}\nPerson 2 Cipher: {ciphertext1}\nPerson 2 Plain: {plaintext1}\n')
print(f'Person 2: {msg2}\nPerson 1 Cipher: {ciphertext2}\nPerson 1 Plain: {plaintext2}')

