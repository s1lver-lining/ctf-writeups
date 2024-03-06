
> *Theorem*
>**Category**: Crypto  
>**Points**: 404  
>**Author**: [Shadowwws](https://twitter.com/Shadowwws7)  
>**Writeup granularity**: Very detailed  
>**Description**: Come try my super AES encryptor  

This simple challenge is about breaking a custom stream cipher **based on a LCG**. I found it very interesting as it highlights an important concept about LCG parameter selection.

I was able to solve it during the competition and even got the 🩸 first blood 🩸 for it !

## First look

We are given a single script `chall.py` and the address of a remote server. This script provides a stream cipher based on [AES-ECB](https://s1lver-lining.github.io/sl/cryptography/symetric/aes/aes-ecb-mode/) and a [Linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator).

### Main cipher

```py
class SuperAES:
    def __init__(self,key,lcg):
        self.aes = AES.new(key,AES.MODE_ECB)
        self.lcg = lcg

    def encrypt(self,plaintext):
        ciphertext = b""
        for i in range(0,len(plaintext),16):
            ciphertext += self.encrypt_block(plaintext[i:i+16])

        return ciphertext

    def encrypt_block(self,block):
        keystream = self.aes.encrypt(int(self.lcg.next_state()).to_bytes(16,"big"))
        return bytes([k^b for k,b in zip(keystream,block)])
```

Here, the keystream is generated using the 16-byte output of the LCG, encrypted with AES. The keystream is then XORed with the plaintext to produce the ciphertext.

[![SuperAES](./_img/superAES-dark.png#gh-dark-mode-only)](./_img/superAES.png)
[![SuperAES](./_img/superAES.png#gh-light-mode-only)](./_img/superAES.png)

Now that we have understood the encryption process, we can say that **there are no major flaws in this system**: This is a stream cipher similar to [AES-CTR](https://s1lver-lining.github.io/sl/cryptography/symetric/aes/aes-ctr-mode/), but with a Linear Congruential Generator instead of a counter. As long as the counter is not reused, the cipher is secure.

[![too strong meme](./_img/too-strong.jpg#meme)](./_img/too-strong.jpg)

Thus, the weakness must be in the LCG.

### Linear Congruential Generator

```py
m = 288493873028852398739253829029106548736
a = int(time.time())
b = a%16
s = random.randint(1,m-1)

class LCG:
    def __init__(self, a, b, m, seed):
        self.a = a
        self.b = b
        self.m = m
        self.state = seed
        self.counter = 0

    def next_state(self):
        ret = self.state
        self.state = (self.a * self.state + self.b) % self.m
        return ret
```

At first glance, this looks like a standard LCG with fixed $m$ and a random seed. However $a$ and $b$ depend on the **current time** and can be easily predicted.

> *Property* Side Note
>
>The fact that $a$ can take a wide range of values make it not have a *full-period* on most cases, as it does not respect the [Hull-Dobell Theorem](https://en.wikipedia.org/wiki/Linear_congruential_generator#Period_length).
>If we were LCM pros, we could already guess that some values of $a$ will be problematic.

## The vulnerability

When we run the LCG on random values for $a$, we notice that **the output becomes constant after some iterations**. After a few tries, we find that this occurs for all values of $a$ when $a = 0 \mod 14$.

This is *simply* because 14 is the product of all prime factors of $m$:

$$\begin{align*}
m &= 288493873028852398739253829029106548736 \\
  &= 2^{66}\ 7^{22} \\
\end{align*}$$

> *Property* Side Note
>
>During the competition, I did not fully understand why this was happening. (In my defence, the author did not either) As I knew this was enough to break the cipher, I continued to work on the exploit.
>If you want to understand what's happening here, you can check out the [Going Further](#going-further) section.

[![Kept exploiting](./_img/kept-exploiting.jpg#meme)](./_img/kept-exploiting.jpg)

Since the output of the LCG is constant, the keystream will be constant as well. This means that the same keystream block will be used to encrypt multiple blocks of the plaintext. There are multiple ways to recover the plaintext, the easiest one is to use what we know about the flag format.

```py
assert len(flag) == 33
assert flag.startswith(b"GCC{")
#assert flag.endswith(b"}") (not in the challenge)
```

## The exploit

The exploit part of this challenge is a **very common** one. We simply have to match the known values of the plaintext to the ciphertext and deduce the keystream bytes at that location. Since the block size (16) does not divide the length of the flag (33), **we recover different parts** of the repeated keystream block.

```py
def compute_flag(data: bytes)->bytes:
    """
    Compute the flag from the given data and known information about it.
    """
    LEN_FLAG  = 33
    LEN_BLOCK = 16

    known_flag = b"GCC{" + b"\xFF" * 28 + b"}" # Unknown bytes are 0xFF
    known_keystream_block = [None for _ in range(16)]

    # Guess the known_keystream_block using the info we know
    for i in range(len(data)):
        if known_flag[i%LEN_FLAG] != 0xFF:
            # Overwrite the previous value, as it might not be in the constant state yet
            known_keystream_block[i%LEN_BLOCK] = data[i] ^ known_flag[i%LEN_FLAG]

    # Compute the flag
    plaintext = bytes([data[i] ^ known_keystream_block[i%LEN_BLOCK] for i in range(len(data))])
    return plaintext[-LEN_FLAG:]
```

Now that we know how to recover the flag when $a = 0 \mod 14$, we can write the full exploit.

Because it is **not possible to predict the exact time at which the server will receive our connection**, we will have to try multiple values. This is also very common in this type of challenges, as network communication and the server time are not always predictable.

```py
import socket
import time

while True: # Break when we find the flag
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("challenges1.gcc-ctf.com", 4001))

    data_recv = s.recv(1024)
    s.send(b"49\n")
    data_recv = s.recv(10000)
    data = bytes.fromhex(data_recv.decode())
    candidate = compute_flag(data)
    if candidate.startswith(b"GCC{"):
        print(candidate)
        break
    time.sleep(.95) # To avoid missing a value, send more
```

Luckily, 14 is quite small and we can try all possible values in reasonable time. ~~Imagine having to wait two minutes for your exploit to complete, yikes.~~

A summary of the code and some test data is available in the [solve.ipynb](./_Files/solve.ipynb) notebook.

## Going Further

After the competition, I really wanted to understand why the output of the LCG becomes constant when the product of the prime factors of $m$ (here 14) divides $a$.

$$m = 2^{66}\ 7^{22} = 56^{22}$$

### b = 0

To explain this, we will first understand why this works for $a = 0 \mod 112$, which is used the [indended solution](https://www.xorminds.com/posts/2024/superaes/). In this simple case, we have both

$$\begin{cases}
a = 0 \mod 14 \\
a = 0 \mod 16 \\
\end{cases}$$

Since $a = 0 \mod 16$, we have $b = 0$ and the LCG becomes:

$$\begin{align*}
x_{i+1} &= a \cdot x_i \mod m \ \ \ \ (1)\\
 &= 56 \cdot 2 \cdot x_i \mod m \\
\end{align*}$$

This means that $x_{22} = 56 ^{22} \cdot 2^{22} \cdot x_0 = m \cdot 2^{22} \cdot x_0 = 0 \mod m$. And because of (1), all the following values will be 0 as well.

### General case

However, we will show that it is not necessary to have $b = 0$ for this to happen. The only requirement for the LCG to become constant is that $a$ is a multiple of 14. From the regular LCG formula:

$$\begin{align*}
x_{i+1} &= a \cdot x_i + b \mod m \\
\end{align*}$$

We can show recursively that for any $i>0$:

$$\begin{align*}
x_{i} &= a^{i} \cdot x_0 + \sum_{j=0}^{i-1} a^{j} \cdot b \mod m \\
\end{align*}$$

When $a = 0 \mod 14$, we have $a = 2 \cdot 7 \cdot k$ for some integer $k$.

Similarly to the previous case, when $i>66$, $a^{i} = 2^{i} \cdot 7^{i} \cdot k^{i} = m \cdot K = 0 \mod m$. This means that the first term becomes 0 as it is a multiple of $m = 2^{66}\ 7^{22}$. Since it was the only term depending on $x_0$, the output becomes predictable:

$$\begin{align*}
x_{i} &= \sum_{j=0}^{i-1} a^{j} \cdot b \mod m \\
 &= b \cdot \sum_{j=0}^{i-1} a^{j} \mod m \\
\end{align*}$$

In addition, the next step will not change the value, as the new first term will also be a multiple of $m$. **This is why the output becomes constant**.

This constant value can also be written as $x_{i} = -b \cdot (a-1)^{-1} \mod m$ when $a-1$ is invertible modulo $m$.

