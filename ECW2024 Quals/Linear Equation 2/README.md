
> *Theorem*
>**Category**: Reverse  

Im just dumping my solve script here. I might add a writeup later.

Please don't judge my code too harshly, the goal was to solve quickly, not to write clean code.


## Solution

### Table generation
```py
from pwn import *
import z3

filename = "./lineq2"
elf = ELF(filename)
context.binary = elf

with open(filename, "rb") as f:
    elf_bytes = f.read()
    elf_bytes = bytearray(elf_bytes)

GHIDRA_OFFSET = 0x100000
DATA_OFFSET_START = 0x3020
DATA_OFFSET_END = 0x296420
PART_SIZE = 0x10500
TARGET_BUFF_SIZE = 0x10000


def generate_part_starts(DATA_OFFSET_START, TARGET_BUFF_SIZE):
    """
    Find all beginings of chunks of size TARGET_BUFF_SIZE composed with 0x00 or 0x01 bytes
    """
    part_starts = []
    current_part_start = DATA_OFFSET_START
    current_part_size = 0
    for i in range(DATA_OFFSET_START, DATA_OFFSET_END):
        if current_part_size == TARGET_BUFF_SIZE:
            part_starts.append((current_part_start))
            current_part_start = i
            current_part_size = 0
        if elf_bytes[i] == 0x00 or elf_bytes[i] == 0x01:
            current_part_size += 1
        else:
            current_part_start = i+1
            current_part_size = 0
    return part_starts

part_starts = generate_part_starts(DATA_OFFSET_START, TARGET_BUFF_SIZE)
part_sizes = []
for i in range(len(part_starts)-1):
    part_sizes.append(part_starts[i+1]-part_starts[i])
part_sizes.append(DATA_OFFSET_END-part_starts[-1])

def find_part_result(part_start, part_size):
    """
    Find the result of the part which is the index of the first 0x01 byte
    """
    result = -1
    for i in range(part_size):
        if elf_bytes[part_start+i] == 0x01:
            if result != -1:
                print("Multiple results found !", result, i)
            result = i
    return result

part_results = []
for part_start in part_starts:
    part_results.append(find_part_result(part_start, TARGET_BUFF_SIZE))

def generate_tables(part_starts, part_sizes):
    """
    Generate tables indexed with thei addresses in the result dictionary
    A part is composed of :
    1 target buff of size TARGET_BUFF_SIZE
    X tables of size 0x200
    1 final table of size 0x100
    """

    tables = {}

    for part_num in range(len(part_starts)):
        tables_total_size = part_sizes[part_num] - TARGET_BUFF_SIZE
        table_count = tables_total_size // 0x200
        
        for i in range(table_count):
            table = []
            for j in range(0x200):
                table.append(elf_bytes[part_starts[part_num]+TARGET_BUFF_SIZE+i*0x200+j])
            tables[part_starts[part_num]+TARGET_BUFF_SIZE+i*0x200] = table
        if tables_total_size % 0x200 == 0x100:
            final_table = []
            for i in range(0x100):
                final_table.append(elf_bytes[part_starts[part_num]+TARGET_BUFF_SIZE+table_count*0x200+i])
            tables[part_starts[part_num]+TARGET_BUFF_SIZE+table_count*0x200] = final_table
    return tables

tables_dict = generate_tables(part_starts, part_sizes)
    
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