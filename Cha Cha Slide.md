# Cha Cha Slide - Writeup

## **Description**

Modern authenticated-encryption ciphers like ChaCha20-Poly1305 are great, but they can quickly fall apart if their limits aren't respected. Can you violate the integrity of a message encrypted by this program?

Additional details will be available after launching your challenge instance.

## Artifacts Provided

- challenge.py - Using ChaCha20, generates a key and a nonce, then encrypts and prints two hardcoded messages. Accepts user input for a third, decrypts it, and prints the flag if it matches the target.

## Initial Thoughts

We looked at the specification for ChaCha20-Poly1305 (the protocol implemented by the server), and noticed that ChaCha20 was used to generate ciphertext, and Poly1305 handled the actual verification. Reading the Wikipedia article for Poly1305, we realized it mentioned the following:

*However, the same key $(r, s)$ must not be reused for two messages. If the adversary learns
$a_1 = (\text{Poly1305}_r(m_1) + s)  \mod 2^{128}\\a_2 = (\text{Poly1305}_r(m_2) + s)  \mod 2^{128}$*

*for $m1 \neq m2$, they can subtract*

$*a_1-a_2\cong \text{Poly1305}_r(m_1) - \text{Poly1305}_r(m_2) \ (\mod 2^{128})$ and find a root of the resulting polynomial to recover a small list of candidates for the secret evaluation point $r$, and from that the secret pad $s$. The adversary can then use this to forge additional messages with high probability.*

Looking at ChaCha20, we realized that the pad $(r, s)$ was generated with the first block containing the key and the nonce - conveniently, we had two differing messages using the same key and nonce. 

After doing some more research on the [crypto stackexchange](https://crypto.stackexchange.com/questions/83629/forgery-attack-on-poly1305-when-the-key-and-nonce-reused)

![Crypto Stackexchange](/images/CryptoStackExchangeChaCha.png)

We found exactly what we needed to implement. 

## Approach A

We then spent some time figuring out how the messages $m_1$ and $m_2$ were built, and seeing if we could actually solve the polynomials. The numbers were too large for most python libraries we found to handle (SageMath included), and we tried solving them modulo $2^{128}$ (which didn’t work), but after reading into how the number  $2^{130}-5$ was used in Poly1305, we realized that the generated polynomials would be easier to solve under this field. We switched to Wolfram for solving, and, after a few attempts, found a valid pair $(r, s)$ that we could use. It was then trivial to generate the ciphertext; since each byte is a simple XOR, $c_3=m_3\oplus m_1\oplus c_1$. We can then add our ciphertext, forged tag, and reused nonce to obtain a valid string.

Most of the attached solve script is the implementation of Poly1305, with manual input so we could plug the polynomial into Wolfram and get a list of candidate $r$ values.


Example:
![Example Woflram](/images/examplechachawolfram.png)

Finally, we also spent a lot of time debugging our implementation of poly1305 since Poly1305 computes the mac for the encrypted ChaCha message very strangely based on the specification found on [Wikipedia](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).

Also, from our readings we knew that forging the new message wasn't always going to happen, so we had to run the script a couple of times in order for it to work.

## Solve Script

```python
import secrets
import hashlib
import struct
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import ChaCha20

# UTILS
def clamp_r(r):
    """Clamps r according to Poly1305 rules."""
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    return r

def poly1305_mac(msg, r, s):
    """Computes the Poly1305 authentication tag for a given message."""
    r = clamp_r(r)  # Clamp r
    s = s & ((1 << 128) - 1)  # Ensure s is 128-bit

    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    
    accumulator = 0
    p = (1 << 130) - 5  # Prime modulus

    for block in blocks:
        n = int.from_bytes(block.ljust(16, b"\x00"), "little")  # Convert to int
        n |= 1 << (8 * len(block))  # Add the extra bit
        accumulator = (accumulator + n) % p
        accumulator = (accumulator * r) % p

    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")

def construct_poly1305_input(C):
    """Constructs the input for Poly1305 in ChaCha20-Poly1305."""
    pad_length = (16 - (len(C) % 16)) % 16  # Padding to next 16-byte boundary
    pad = b"\x00" * pad_length  # Zero padding
    len_A = struct.pack("<Q", 0)
    len_C = struct.pack("<Q", len(C))  # 64-bit little-endian length of C

    return C + pad + len_A + len_C

def getBlocks(msg):
    vals = [] # Clamp r
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    for block in blocks:
        n = int.from_bytes(block.ljust(16, b"\x00"), "little")  # Convert to int
        n |= 1 << (8 * len(block))  # Add the extra bit
        vals.append(n)

    return vals

def recover_s(msg, r, tag):
    """Computes the Poly1305 authentication tag for a given message."""
    r = clamp_r(r)  # Clamp r

    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    
    accumulator = 0
    p = (1 << 130) - 5  # Prime modulus

    for block in blocks:
        n = int.from_bytes(block.ljust(16, b"\x00"), "little")  # Convert to int
        n |= 1 << (8 * len(block))  # Add the extra bit
        accumulator = (accumulator + n) % p
        accumulator = (accumulator * r) % p

    s = (int.from_bytes(tag,byteorder="little") - accumulator) % (1 << 128)
    return s

# solver

messages = [
    "Did you know that ChaCha20-Poly1305 is an authenticated encryption algorithm?",
    "That means it protects both the confidentiality and integrity of data!",
]

goal = "But it's only secure if used correctly!"

user = bytes.fromhex(input("What is CT1: "))
ct1 = user[:-28]
tag1 = user[-28:-12]
nonce = user[-12:]

user = bytes.fromhex(input("What is CT2: "))
ct2 = user[:-28]
tag2 = user[-28:-12]
nonce = user[-12:]

####################################################################################################
####################################### Solving for R ##############################################
####################################################################################################

print("-"*20+"R Solver"+"-"*20)

coeffs = [a-b for a,b in zip(getBlocks(construct_poly1305_input(ct1)),getBlocks(construct_poly1305_input(ct2)))]
target = (int.from_bytes(tag1,byteorder="little")-int.from_bytes(tag2,byteorder="little"))

if target < 0:
    target += 2**128

print(coeffs)
print("-"*20+"Polynomial"+"-"*20)

poly = ""
for i in range(len(coeffs)):
    poly += ("+" if coeffs[i] > 0 else "") + str(coeffs[i])+"*x^"+str(len(coeffs)-i)

poly += ("" if target > 0 else "+") +str(-target)

# Prints polynomial to be copied pasted into Wolfram Mathmatica
print("poly = "+poly)

print("-"*20+"Possible R"+"-"*20)
possible_R = []

# Enter possible R values found by Wolfram
while True:
    inp = input("enter possible R (or done if done): ")
    if inp == "done": break
    inp = int(inp)
    # Hacky check to reduce false positives
    if clamp_r(inp) == inp:
        possible_R.append(inp)
    else:
        print("fail")

print("-"*20+"checking R values"+"-"*20)

#TODO: actually check the r values
rec_r = possible_R[0]

print("-"*20+"Solving Time"+"-"*20)

# Forging

print("-"*20+"Forging Time"+"-"*20)

goal = "But it's only secure if used correctly!"
ctf = bytes(bytearray([a^b for a,b in zip(messages[0].encode(),ct1)]))
ctf = bytes(bytearray([a^b for a,b in zip(ctf,goal.encode())]))

rec_s = recover_s(construct_poly1305_input(ct1), rec_r, tag1)
tagf = poly1305_mac(construct_poly1305_input(ctf),rec_r,rec_s)
forged = ctf.hex()+tagf.hex()+nonce.hex()

print(forged)
```

## Flag

![sovling](/images/ChaChaSolving.png)
![flag](/images/chachasolved.png)