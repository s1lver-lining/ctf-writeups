
> *Theorem*
>**Category**: Crypto  
>**Author**: [Amosys](https://www.amossys.fr/)  

We are provided with the code of a Javacard Applet.


## First look

The applet is handling [APDU](https://fr.wikipedia.org/wiki/Application_Protocol_Data_Unit) commands to perform the verification of a PIN code. If the PIN is correct, the user have access to the getFlag command:

```java
switch (buffer[ISO7816.OFFSET_INS]) {
    case GET_FLAG:
        if(is_pin_valid(apdu))
            getFlag(apdu);
        return;
    case VERIFY:
        // First, we need to check the PIN code to ensure the user is allowed
        verify(apdu);
        return;
    case WRITE_FLAG:
        writeSecretData(apdu);
        return;
    default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
}
```

## Exploit

When trying to send some PIN, we notice that some inputs take a long time to process. This is a clear indication that there is a timing attack vulnerability.

We can create a simple script to get the PIN, character by character, by measuring the time it takes to process the command.

```python
from pwn import *

def send_cmd(cmd):
    conn = remote("challenges.challenge-ecw.eu", 4242, level="warn")

    conn.sendline(cmd)
    conn.shutdown()

    data = conn.recvall()
    if b"an APDU !\n" in data:
        """
        [>] Sending command 802000000109FF
        CommmandAPDU: 7 bytes, nc=1, ne=255
        [<] Status Code: 0x6300
        [i] Response time: 200.476108ms
        [i] No data received from Card
        """
        return data.split(b"an APDU !\n")[1].strip()
    else:
        return data


CLA = b"80"
INS_VERIFY = b"20"
INS_WRITE = b"30"
INS_GET = b"50"

def gen_apdu(ins, data: bytes, end=b"FF"):
    return CLA + ins + b"0000" + bytes([len(data)]).hex().encode() + data.hex().encode() + end

pin_code = b""
while True:
    times = []
    for i in range(10):
        cmd = gen_apdu(INS_VERIFY, pin_code + bytes([i]))
        res = send_cmd(cmd)
        time = float(res.split(b"Response time: ")[1].split(b"ms")[0])
        print(f"Pin: {pin_code + bytes([i])}, Time: {time}")
        times.append(time)
    print(times)
    max_time = max(times)
    pin_code += bytes([times.index(max_time)])
    print(f"Pin code: {pin_code}")
    print()
```

We find the following PIN code: `\x09\x03\x05\x05\x01\x08`. We can now use this PIN code to get the flag:

```python
cmd = gen_apdu(INS_VERIFY, b'\t\x03\x05\x05\x01\x08') + b" " + gen_apdu(INS_GET, b'', end=b"0FFF")
print(cmd)
print(send_cmd(cmd).decode())
```

```sh
b'8020000006090305050108FF 80500000000FFF'
[>] Sending command 8020000006090305050108FF
CommmandAPDU: 12 bytes, nc=6, ne=255
[<] Status Code: 0x9000
[i] Response time: 1200.549773ms
[i] No data received from Card
[>] Sending command 80500000000FFF
CommmandAPDU: 7 bytes, nc=0, ne=4095
[<] Status Code: 0x9000
[i] Response time: 0.190323ms
[<] Data received from card: 0xFF, ...
```

The data is an JPG image of a SmartCard with `ECW{D4mn_I_G0t_D3laaaaays}` written on it.