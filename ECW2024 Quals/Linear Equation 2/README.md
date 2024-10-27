
> *Theorem*
>**Category**: Reverse  

Im just dumping my solve script here. I might add a writeup later.

Please don't judge my code too harshly, the goal was to solve quickly, not to write clean code.


## Solution

### Table generation
```py
import z3

def compute(inp:list):
    result = [0] * 32
    result[0] = (inp[20] ^ 0x40) * 0xec + (inp[21] ^ 0x40) * -0x84 + (inp[14] ^ 0x40) * -0x79 + (inp[22] ^ 0x40) * -0x1a + (inp[21] ^ 0x40) * -0x40
    result[1] = (inp[5] ^ 0x6b) * 0xc + (inp[6] ^ 0x6b) * 0x59 + (inp[8] ^ 0x6b) * 0xdc + (inp[17] ^ 0x6b) * -0x4a + (inp[15] ^ 0x6b) * 0xa2
    result[2] = (inp[9] ^ 0xf7) * -0x60 + (inp[30] ^ 0xf7) * -0xc1 + (inp[5] ^ 0xf7) * -0xea + (inp[14] ^ 0xf7) * 199 + (inp[27] ^ 0xf7) * 0xbf
    result[3] = (inp[12] ^ 0x6e) * 0x25 + (inp[11] ^ 0x6e) * -0x80 + (inp[5] ^ 0x6e) * 0x88 + (inp[7] ^ 0x6e) * 0x6a
    result[4] = (inp[4] ^ 0x24) * -0x7b + (inp[28] ^ 0x24) * 0xd7 + (inp[12] ^ 0x24) * -0xfa + (inp[11] ^ 0x24) * 0xf7 + (inp[13] ^ 0x24) * -4
    result[5] = (inp[16] ^ 0x54) * 0x20 + (inp[24] ^ 0x54) * -0x86 + (inp[11] ^ 0x54) * -0x94 + (inp[8] ^ 0x54) * -0x24 + (inp[26] ^ 0x54) * 0x85
    result[6] = (inp[22] ^ 1) * 0x139 + (inp[17] ^ 1) * -0xd4 + (inp[7] ^ 1) * -5 + (inp[13] ^ 1) * -0xa4
    result[7] = (inp[15] ^ 0xa7) * -0xd8 + (inp[19] ^ 0xa7) * 0xd2 + (inp[4] ^ 0xa7) * 0x81 + (inp[27] ^ 0xa7) * -0xde
    result[8] = (inp[11] ^ 0x27) * 0xb9 + (inp[26] ^ 0x27) * -0xb6 + (inp[21] ^ 0x27) * -0x36 + (inp[21] ^ 0x27) * 0x4f + (inp[10] ^ 0x27) * 0x8e
    result[9] = (inp[22] ^ 0x8d) * 0xc6 + (inp[21] ^ 0x8d) * -0x15 + (inp[11] ^ 0x8d) * 0x26 + (inp[11] ^ 0x8d) * 0x71 + (inp[24] ^ 0x8d) * -0xb6
    result[10] = (inp[18] ^ 200) * -0x3a + (inp[13] ^ 200) * -0x5b + (inp[27] ^ 200) * -0xca + (inp[20] ^ 200) * 0x16e
    result[11] = (inp[27] ^ 0x6d) * 0xcc + (inp[13] ^ 0x6d) * -0x7c + (inp[5] ^ 0x6d) * -0x55 + (inp[21] ^ 0x6d) + (inp[21] ^ 0x6d) * 2 + (inp[24] ^ 0x6d) * 0xf6
    result[12] = (inp[29] ^ 0x66) * -0xe7 + (inp[6] ^ 0x66) * 0xc4 + (inp[16] ^ 0x66) * 0xf3 + (inp[26] ^ 0x66) * -0x4b + (inp[20] ^ 0x66) * -0x5d
    result[13] = (inp[22] ^ 0x1f) * 0xcc + (inp[21] ^ 0x1f) * -0xfd + (inp[25] ^ 0x1f) * -0x6a + (inp[14] ^ 0x1f) * -0x3d + (inp[13] ^ 0x1f) * 0x7d
    result[14] = (inp[15] ^ 0x2b) * -0xcf + (inp[13] ^ 0x2b) * 0x93 + (inp[17] ^ 0x2b) * 0x8f + (inp[9] ^ 0x2b) * 0xb2 + (inp[30] ^ 0x2b) * 0x1e
    result[15] = (inp[24] ^ 0xd) * -0x5a + (inp[30] ^ 0xd) * -100 + (inp[19] ^ 0xd) * -0x24 + (inp[21] ^ 0xd) * -0x6a
    result[16] = (inp[21] ^ 0x1e) * 0xe + (inp[9] ^ 0x1e) * 0x24 + (inp[12] ^ 0x1e) * 0xf6 + (inp[26] ^ 0x1e) * -0x35 + (inp[23] ^ 0x1e) * -0x1f
    result[17] = (inp[7] ^ 0x1f) * 0x8a + (inp[8] ^ 0x1f) * 0x71 + (inp[29] ^ 0x1f) * 0x7c + (inp[17] ^ 0x1f) * 6 + (inp[10] ^ 0x1f) * 0x95
    result[18] = (inp[6] ^ 0x23) * -0x49 + (inp[27] ^ 0x23) * -0x32 + (inp[24] ^ 0x23) * -0x1a + (inp[19] ^ 0x23) * 0xe8 + (inp[4] ^ 0x23) * -0xa6
    result[19] = (inp[28] ^ 0x87) * -0x46 + (inp[18] ^ 0x87) + (inp[18] ^ 0x87) * 8 + (inp[30] ^ 0x87) * 0xd4 + (inp[23] ^ 0x87) * -0x7c + (inp[24] ^ 0x87) * 0x1e
    result[20] = (inp[24] ^ 0xe9) * 0x20 + (inp[17] ^ 0xe9) * -99 + (inp[26] ^ 0xe9) * -0xae + (inp[9] ^ 0xe9) * -0x92 + (inp[8] ^ 0xe9) * 0xd7
    result[21] = (inp[23] ^ 0x3e) * -0xd8 + (inp[26] ^ 0x3e) * 10 + (inp[19] ^ 0x3e) * -9 + (inp[11] ^ 0x3e) * -0x10 + (inp[8] ^ 0x3e) * 0xdc
    result[22] = (inp[25] ^ 0xdf) * 0x5f + (inp[27] ^ 0xdf) * 0x43 + (inp[4] ^ 0xdf) * -0x94 + (inp[11] ^ 0xdf) * 0x50
    result[23] = (inp[19] ^ 0x6a) * 0x45 + (inp[4] ^ 0x6a) * 0x52 + (inp[17] ^ 0x6a) * -0xa9 + (inp[23] ^ 0x6a) * 0x6e + (inp[14] ^ 0x6a) * -0xdb
    result[24] = (inp[27] ^ 0x1b) * 0xd7 + (inp[29] ^ 0x1b) * -0x98 + (inp[11] ^ 0x1b) * 0x20 + (inp[23] ^ 0x1b) * 0x4c + (inp[4] ^ 0x1b) * 0x6e
    result[25] = (inp[4] ^ 1) * -0x11 + (inp[23] ^ 1) * -0x9e + (inp[7] ^ 1) * -0x87 + (inp[17] ^ 1) * -0xcd + (inp[18] ^ 1) * 0x93
    result[26] = (inp[5] ^ 0xd) * 0x2f + (inp[9] ^ 0xd) * 0x51 + (inp[16] ^ 0xd) * -0xf1 + (inp[8] ^ 0xd) * 0xff + (inp[21] ^ 0xd) * -0x12
    result[27] = inp[0]
    result[28] = inp[1]
    result[29] = inp[2]
    result[30] = inp[3]
    result[31] = inp[31]
    return result

Y = [
    0xca9, 0x5ae1, -0x5912, 0x5010, 0x3909, -0x2439, 0x1374, -0x2733, 0x3746, 0x578c, 0x35e4, 0x3a3a, -0x4997, 0x517, 0x45fd, -0x7f12, 0x2b33, 0x654d, -0x17e1, 0x6dce, -0x5c96, -0x6ae, 0x5e9c, -0x280d, 0x525e, -0x5132, -0xf85, ord("E"), ord("C"), ord("W"), ord("{"), ord("}")
]

X = [z3.BitVec(f"X{i}", 8) for i in range(32)]
s = z3.Solver()
z3_result = compute(X)

for i in range(32):
    s.add(X[i] >= 0x20)
    s.add(X[i] <= 0x7e)

for i in range(1, 32):
    s.add(z3_result[i] == Y[i])
print(s.check())

m = s.model()

for i in range(32):
    print(chr(m[X[i]].as_long()), end="")
    
```

### Condition generation

```py
def generate_conditions(tables_dict, inputs:list):
    tables = {}
    # Add GHIDRA_OFFSET to the addresses
    for key in tables_dict.keys():
        tables[key+GHIDRA_OFFSET] = tables_dict[key]

    perm_values = {
        3: inputs[36],
        4: inputs[7],
        5: inputs[18],
        7: inputs[43],
        8: inputs[26],
        9: inputs[33],
        10: inputs[15],
        11: inputs[5],
        12: inputs[31],
        13: inputs[39],
        14: inputs[6],
        15: inputs[14],
        16: inputs[32],
        17: inputs[22],
        18: inputs[19],
        19: inputs[42],
        20: inputs[25],
        21: inputs[30],
        22: inputs[28],
        23: inputs[13],
        24: inputs[23],
        25: inputs[37],
        26: tables[0x0021a020][inputs[28]],
        27: inputs[16],
        28: inputs[21],
        29: inputs[35],
        30: inputs[41],
        31: inputs[27],
        32: inputs[20],
        33: inputs[9],
        34: inputs[34],
        35: inputs[24],
        36: inputs[11],
    }

    perm = lambda x: perm_values[x]
    inp = lambda x: inputs[x]

    conditions = {
        0x00103020: (((((tables[0x00113020][tables[0x00113420][perm(27)]*2]) + (tables[0x002bdc20][tables[0x00113420][perm(31)]*2])) - (tables[0x00113220][tables[0x00113420][perm(9)]*2])) - (tables[0x001b6c20][tables[0x00113420][perm(27)]*2])) - (tables[0x0023a820][tables[0x00113420][perm(22)]*2])),
        0x00113520: (((((tables[0x00123520][tables[0x001f8f20][perm(16)]*2]) + (tables[0x00123920][tables[0x001f8f20][perm(15)]*2])) - (tables[0x00123720][tables[0x001f8f20][inp(12)]*2])) - (tables[0x00342620][tables[0x001f8f20][perm(7)]*2])) - (tables[0x00353320][tables[0x001f8f20][perm(25)]*2])),
        0x00123b20: ((((tables[0x00133b20][tables[0x00133f20][perm(9)]*2]) - ((tables[0x00133d20][tables[0x00133f20][perm(9)]*2]) + (tables[0x00374920][tables[0x00133f20][perm(16)]*2]))) - (tables[0x00219620][tables[0x00133f20][perm(29)]*2])) - (tables[0x00363c20][tables[0x00133f20][inp(8)]*2])),
        0x00134020: ((((tables[0x00144020][tables[0x00144620][perm(3)]*2]) - ((tables[0x00321620][tables[0x00144620][perm(8)]*2]) + (tables[0x00144420][tables[0x00144620][perm(17)]*2]))) - (tables[0x00144220][tables[0x00144620][perm(13)]*2])) - (tables[0x001e8320][tables[0x00144620][perm(34)]*2])),
        0x00144720: (((((tables[0x00385020][tables[0x00154920][perm(17)]*2]) + (tables[0x0026b920][tables[0x00154920][perm(11)]*2])) - (tables[0x001e8920][tables[0x00154920][perm(8)]*2])) - (tables[0x00374520][tables[0x00154920][perm(22)]*2])) - (tables[0x00154720][tables[0x00154920][perm(4)]*2])),
        0x00154a20: (((((tables[0x00164a20][tables[0x00165220][perm(31)]*2]) + (tables[0x00164e20][tables[0x00165220][perm(34)]*2])) - (tables[0x00165020][tables[0x00165220][perm(31)]*2])) - (tables[0x0022a520][tables[0x00165220][perm(7)]*2])) - (tables[0x00164c20][tables[0x00165220][perm(17)]*2])),
        0x00165320: ((((tables[0x001a6220][tables[0x00175920][perm(7)]*2]) + (tables[0x00175720][tables[0x00175920][perm(28)]*2]) + (tables[0x00175320][tables[0x00175920][perm(34)]*2])) - (tables[0x00175520][tables[0x00175920][perm(30)]*2])) - (tables[0x00374720][tables[0x00175920][perm(20)]*2])),
        0x00175a20: ((((tables[0x00342c20][tables[0x00185e20][inp(17)]*2]) + (tables[0x00185c20][tables[0x00185e20][perm(14)]*2]) + (tables[0x00185a20][tables[0x00185e20][perm(20)]*2])) - (tables[0x002ef720][tables[0x00185e20][perm(24)]*2])) - (tables[0x00374520][tables[0x00185e20][perm(15)]*2])),
        0x00185f20: (((((tables[0x00195f20][tables[0x00196120][perm(24)]*2]) + (tables[0x00321a20][tables[0x00196120][perm(4)]*2])) - (tables[0x00385220][tables[0x00196120][perm(13)]*2])) - (tables[0x002df020][tables[0x00196120][perm(16)]*2])) - (tables[0x00363c20][tables[0x00196120][perm(24)]*2])),
        0x00196220: (((((tables[0x001a6420][tables[0x002eff20][inp(17)]*2]) + (tables[0x001a6a20][tables[0x002eff20][perm(29)]*2])) - (tables[0x001a6820][tables[0x002eff20][perm(34)]*2])) - (tables[0x001a6620][tables[0x002eff20][perm(14)]*2])) - (tables[0x001a6220][tables[0x002eff20][perm(32)]*2])),
        0x001a6c20: (((((tables[0x001b7220][tables[0x001b7420][perm(19)]*2]) + (tables[0x001b6e20][tables[0x001b7420][perm(30)]*2])) - (tables[0x002ad120][tables[0x001b7420][perm(36)]*2])) - (tables[0x001b7020][tables[0x001b7420][perm(19)]*2])) - (tables[0x001b6c20][tables[0x001b7420][inp(40)]*2])),
        0x001b7520: ((((tables[0x001c7920][tables[0x001c7b20][perm(29)]*2]) + (tables[0x00352f20][tables[0x001c7b20][inp(29)]*2]) + (tables[0x0029ce20][tables[0x001c7b20][perm(7)]*2])) - (tables[0x001c7720][tables[0x001c7b20][perm(22)]*2])) - (tables[0x001c7520][tables[0x001c7b20][perm(5)]*2])),
        0x001c7c20: ((((tables[0x00332120][tables[0x001d8220][perm(27)]*2]) + (tables[0x002ce520][tables[0x001d8220][perm(30)]*2]) + (tables[0x001d7e20][tables[0x001d8220][perm(28)]*2])) - (tables[0x001d8020][tables[0x001d8220][perm(22)]*2])) - (tables[0x001d7c20][tables[0x001d8220][perm(36)]*2])),
        0x001d8320: ((((tables[0x001e8720][tables[0x002be220][perm(13)]*2]) + (tables[0x00321a20][tables[0x002be220][perm(10)]*2]) + (tables[0x001e8320][tables[0x002be220][perm(12)]*2])) - (tables[0x001e8920][tables[0x002be220][perm(7)]*2])) - (tables[0x001e8520][tables[0x002be220][perm(24)]*2])),
        0x001e8b20: ((((tables[0x00311120][tables[0x001f8f20][inp(8)]*2]) + (tables[0x00310b20][tables[0x001f8f20][perm(10)]*2]) + (tables[0x001f8d20][tables[0x001f8f20][perm(28)]*2])) - (tables[0x00352f20][tables[0x001f8f20][perm(27)]*2])) - (tables[0x001f8b20][tables[0x001f8f20][inp(10)]*2])),
        0x001f9020: (((((tables[0x00209020][tables[0x00332520][perm(29)]*2]) + (tables[0x00209420][tables[0x00332520][perm(3)]*2])) - (tables[0x00209220][tables[0x00332520][perm(5)]*2])) - (tables[0x00395f20][tables[0x00332520][perm(28)]*2])) - (tables[0x00209420][tables[0x00332520][perm(25)]*2])),
        0x00209620: ((((tables[0x00219820][tables[0x0021a020][perm(8)]*2]) + (tables[0x00219e20][perm(26) * 2]) + (tables[0x00219620][tables[0x0021a020][perm(8)]*2])) - (tables[0x00219c20][perm(26) * 2])) - (tables[0x00219a20][perm(26) * 2])),
        0x0021a120: (((((tables[0x0022a120][tables[0x0022a720][perm(21)]*2]) + (tables[0x0022a520][tables[0x0022a720][perm(3)]*2])) - (tables[0x0022a320][tables[0x0022a720][perm(3)]*2])) - (tables[0x00385020][tables[0x0022a720][perm(21)]*2])) - (tables[0x0028c520][tables[0x0022a720][perm(14)]*2])),
        0x0022a820: ((((tables[0x0023ac20][tables[0x0023ae20][perm(18)]*2]) - ((tables[0x0023aa20][tables[0x0023ae20][perm(35)]*2]) + (tables[0x002ce520][tables[0x0023ae20][perm(17)]*2]))) - (tables[0x00300020][tables[0x0023ae20][perm(3)]*2])) - (tables[0x0023a820][tables[0x0023ae20][perm(3)]*2])),
        0x0023af20: ((((tables[0x0024b120][tables[0x0024b320][perm(20)]*2]) + (tables[0x00353520][tables[0x0024b320][perm(24)]*2]) + (tables[0x002df220][tables[0x0024b320][perm(17)]*2])) - (tables[0x0024af20][tables[0x0024b320][perm(15)]*2])) - (tables[0x00300020][tables[0x0024b320][perm(27)]*2])),
        0x0024b420: (((((tables[0x0028c320][tables[0x0025b620][perm(8)]*2]) + (tables[0x0025b420][tables[0x0025b620][perm(20)]*2])) - (tables[0x002efb20][tables[0x0025b620][perm(36)]*2])) - (tables[0x00310d20][tables[0x0025b620][perm(33)]*2])) - (tables[0x002ef720][tables[0x0025b620][inp(38)]*2])),
        0x0025b720: ((((tables[0x00321a20][tables[0x0026bd20][perm(32)]*2]) + (tables[0x0026bb20][tables[0x0026bd20][perm(17)]*2]) + (tables[0x0026b720][tables[0x0026bd20][perm(23)]*2])) - (tables[0x0026b920][tables[0x0026bd20][perm(7)]*2])) - (tables[0x0026bb20][tables[0x0026bd20][perm(8)]*2])),
        0x0026be20: (((((tables[0x00395f20][tables[0x0027c220][perm(7)]*2]) + (tables[0x0027be20][tables[0x0027c220][perm(35)]*2])) - (tables[0x0027c020][tables[0x0027c220][perm(20)]*2])) - (tables[0x002efb20][tables[0x0027c220][perm(17)]*2])) - (tables[0x00353520][tables[0x0027c220][perm(33)]*2])),
        0x0027c320: ((((tables[0x002efb20][tables[0x0028c720][perm(19)]*2]) + (tables[0x0029cc20][tables[0x0028c720][perm(21)]*2]) + (tables[0x0028c320][tables[0x0028c720][perm(16)]*2])) - (tables[0x0028c520][tables[0x0028c720][perm(29)]*2])) - (tables[0x002efd20][tables[0x0028c720][perm(19)]*2])),
        0x0028c820: (((((tables[0x0029c820][tables[0x0029d020][perm(31)]*2]) + (tables[0x0029ca20][tables[0x0029d020][perm(15)]*2])) - (tables[0x0029ce20][tables[0x0029d020][perm(25)]*2])) - (tables[0x0029cc20][tables[0x0029d020][perm(8)]*2])) - (tables[0x002ce720][tables[0x0029d020][perm(21)]*2])),
        0x0029d120: ((((tables[0x00385620][tables[0x002ad920][perm(15)]*2]) - ((tables[0x002ad520][tables[0x002ad920][perm(12)]*2]) + (tables[0x002ad720][tables[0x002ad920][perm(23)]*2]))) - (tables[0x002ad320][tables[0x002ad920][perm(19)]*2])) - (tables[0x002ad120][tables[0x002ad920][perm(9)]*2])),
        0x002ada20: (((((tables[0x002ef720][tables[0x002be220][perm(8)]*2]) + (tables[0x002be020][tables[0x002be220][perm(7)]*2])) - (tables[0x002bde20][tables[0x002be220][perm(13)]*2])) - (tables[0x002bdc20][tables[0x002be220][perm(11)]*2])) - (tables[0x002bda20][tables[0x002be220][perm(21)]*2])),
        0x002be320: (((((tables[0x002ce320][tables[0x002ce920][perm(12)]*2]) + (tables[0x002ce520][tables[0x002ce920][perm(20)]*2])) - (tables[0x00374b20][tables[0x002ce920][perm(23)]*2])) - (tables[0x002ce720][tables[0x002ce920][perm(25)]*2])) - (tables[0x00374320][tables[0x002ce920][perm(25)]*2])),
        0x002cea20: (((tables[0x002dee20][tables[0x002df420][perm(11)]*2]) + (tables[0x002df220][tables[0x002df420][perm(15)]*2]) + (tables[0x002dec20][tables[0x002df420][perm(18)]*2]) + (tables[0x002dea20][tables[0x002df420][perm(28)]*2])) - (tables[0x002df020][tables[0x002df420][perm(20)]*2])),
        0x002df520: ((((tables[0x002ef920][tables[0x002eff20][perm(32)]*2]) + (tables[0x002efd20][tables[0x002eff20][perm(19)]*2]) + (tables[0x002ef520][tables[0x002eff20][perm(3)]*2])) - (tables[0x002efb20][tables[0x002eff20][perm(34)]*2])) - (tables[0x002ef720][tables[0x002eff20][perm(36)]*2])),
        0x002f0020: ((((tables[0x00300220][tables[0x00300820][perm(3)]*2]) + (tables[0x00300620][tables[0x00300820][perm(5)]*2]) + (tables[0x00300020][tables[0x00300820][perm(13)]*2])) - (tables[0x00300420][tables[0x00300820][perm(11)]*2])) - (tables[0x00321420][tables[0x00300820][perm(36)]*2])),
        0x00300920: (((((tables[0x00310b20][tables[0x00311320][perm(33)]*2]) + (tables[0x00311120][tables[0x00311320][perm(19)]*2])) - (tables[0x00310f20][tables[0x00311320][perm(36)]*2])) - (tables[0x00310d20][tables[0x00311320][perm(16)]*2])) - (tables[0x00310920][tables[0x00311320][perm(32)]*2])),
        0x00311420: (((tables[0x00321a20][tables[0x00321c20][inp(10)]*2]) + (tables[0x00385420][tables[0x00321c20][perm(10)]*2]) + (tables[0x00321820][tables[0x00321c20][perm(11)]*2]) + (tables[0x00321420][tables[0x00321c20][perm(12)]*2])) - (tables[0x00321620][tables[0x00321c20][perm(29)]*2])),
        0x00321d20: (((((tables[0x00331f20][tables[0x00332520][inp(40)]*2]) + (tables[0x00332320][tables[0x00332520][perm(4)]*2])) - (tables[0x00332120][tables[0x00332520][perm(32)]*2])) - (tables[0x00331d20][tables[0x00332520][perm(29)]*2])) - (tables[0x00385020][tables[0x00332520][perm(35)]*2])),
        0x00332620: ((((tables[0x00352f20][tables[0x00342e20][perm(34)]*2]) + (tables[0x00342c20][tables[0x00342e20][perm(3)]*2]) + (tables[0x00342620][tables[0x00342e20][perm(35)]*2])) - (tables[0x00342a20][tables[0x00342e20][perm(8)]*2])) - (tables[0x00342820][tables[0x00342e20][perm(16)]*2])),
        0x00342f20: (((((tables[0x00353120][tables[0x00353920][perm(23)]*2]) + (tables[0x00353720][tables[0x00353920][perm(23)]*2])) - (tables[0x00353520][tables[0x00353920][perm(9)]*2])) - (tables[0x00353320][tables[0x00353920][perm(28)]*2])) - (tables[0x00352f20][tables[0x00353920][perm(20)]*2])),
        0x00353a20: ((((tables[0x00364020][tables[0x00364220][perm(19)]*2]) - ((tables[0x00374b20][tables[0x00364220][perm(19)]*2]) + (tables[0x00363e20][tables[0x00364220][perm(27)]*2]))) - (tables[0x00363c20][tables[0x00364220][perm(16)]*2])) - (tables[0x00363a20][tables[0x00364220][inp(4)]*2])),
        0x00364320: ((((tables[0x00374520][tables[0x00374d20][perm(18)]*2]) - ((tables[0x00374920][tables[0x00374d20][perm(8)]*2]) + (tables[0x00374b20][tables[0x00374d20][perm(34)]*2]))) - (tables[0x00374720][tables[0x00374d20][perm(32)]*2])) - (tables[0x00374320][tables[0x00374d20][perm(16)]*2])),
        0x00374e20: (((((tables[0x00385220][tables[0x00385820][inp(38)]*2]) + (tables[0x00385620][tables[0x00385820][perm(32)]*2])) - (tables[0x00385420][tables[0x00385820][perm(15)]*2])) - (tables[0x00385020][tables[0x00385820][perm(36)]*2])) - (tables[0x00384e20][tables[0x00385820][perm(33)]*2])),
        0x00385920: ((((tables[0x00395f20][tables[0x00396320][inp(12)]*2]) + (tables[0x00396120][tables[0x00396320][perm(17)]*2]) + (tables[0x00395d20][tables[0x00396320][perm(31)]*2])) - (tables[0x00395b20][tables[0x00396320][perm(8)]*2])) - (tables[0x00395920][tables[0x00396320][perm(7)]*2]))
    }

    return conditions

conditions = generate_conditions(tables_dict, [0x00]*44)

# Check that all the keys correspond to the addresses of the parts
for key in conditions.keys():
    if key not in [x+GHIDRA_OFFSET for x in part_starts]:
        print("ERROR: ", hex(key))
```

### Z3 solver

```py
s = z3.Solver()

z3_tables = {}
for key in tables_dict.keys():
    if len(tables_dict[key]) == 0x200:
        z3_tables[key] = z3.Array("array_"+hex(key), z3.BitVecSort(16), z3.BitVecSort(8))
    else:
        z3_tables[key] = z3.Array("array_"+hex(key), z3.BitVecSort(8), z3.BitVecSort(16))
    

for key in z3_tables.keys():
    for i in range(len(tables_dict[key])):
        s.add(z3_tables[key][i] == tables_dict[key][i])

z3_inputs = [z3.BitVec("input_"+str(i), 8) for i in range(45)]

s.add(z3_inputs[0] == ord("E"))
s.add(z3_inputs[1] == ord("C"))
s.add(z3_inputs[2] == ord("W"))
s.add(z3_inputs[3] == ord("{"))
s.add(z3_inputs[44] == ord("}"))

for i in range(45):
    s.add(z3_inputs[i] >= 0x20)
    s.add(z3_inputs[i] < 0x7f)

conditions = generate_conditions(z3_tables, z3_inputs)

for key in conditions.keys():
    s.add(conditions[key] == part_results[part_starts.index(key-GHIDRA_OFFSET)])

print(s.check())

m = s.model()
res = ""
for i in range(45):
    res += chr(m[z3_inputs[i]].as_long())
print(res)
```

```sh
sat
ECW{4rR4Ys_4r3_N0_Pr0bl3m_F0r_sUp3er_h4Xx0Rs}
```