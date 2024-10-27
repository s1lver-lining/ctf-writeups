
> *Theorem*
>**Category**: Reverse  

Im just dumping my solve script here. I might add a writeup later.

Please don't judge my code too harshly, the goal was to solve quickly, not to write clean code.


## Solution

```py {filename="solve.py"}
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

```sh
sat
ECW{l1N34r_C0Nstr41n15_4r3_345y}
```