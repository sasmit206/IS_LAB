# Use a Hill cipher to encipher the message "We live in an insecure world". Use the following
# key:
# 𝐾 = [03 03 2 07]

k = []
m = int(input("Enter the dimension of Key matrix: "))

for i in range(m):
    subarr = []
    for j in range(m):
        subarr.append(int(input()))
    k.append(subarr)

def hill_encrypt(plaintext):
    count = (m - len(plaintext) % m) % m
    plaintext += 'x' * count

    #ciphertext:
    ciphertext = ''
    for i in range(0,len(plaintext),m):
        temp = []
        c = []
        for j in range(m):
            temp.append(ord(plaintext[i+j]) - ord('a'))

        for row in range(m):
            total = 0

            for col in range(m):
                total += k[row][col] * temp[col]

            c.append(total % 26)

        for x in c:
            ciphertext += chr(x+ord('a'))

    return ciphertext

def hill_decrypt(ciphertext):
    count = (m - len(ciphertext) %m ) % m
    plaintext = ''
    

def main():
    plaintext = input("Enter the plaintext: ").lower().replace(' ', '')
    ciphertext = hill_encrypt(plaintext)
    print(ciphertext)

main()