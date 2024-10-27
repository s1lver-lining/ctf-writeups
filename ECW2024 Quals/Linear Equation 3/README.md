
> *Theorem*
>**Category**: Reverse  

Im just dumping my solve script here. I might add a writeup later.

Please don't judge my code too harshly, the goal was to solve quickly, not to write clean code.


## Solution

### Utility

```py
import ctypes
import mmap
import tqdm
import z3

filename = "lineq3"

with open(filename, "rb") as f:
    data = f.read()

GHIDRA_OFFSET = 0x400000

def get_addr(address):
    return address-GHIDRA_OFFSET

def get_bytes(address, length=1):
    return data[get_addr(address):get_addr(address)+length]


def execute_at(addr, param):

    code = get_bytes(addr, 0x80)
    buf = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)

    ftype = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    fpointer = ctypes.c_void_p.from_buffer(buf)

    f = ftype(ctypes.addressof(fpointer))

    buf.write(code)

    r = f(param)

    del fpointer
    buf.close()
    return (r)
```

### Find the prototype of each function

[`L.py`](./_Files/L.py) contains the strings of the functions, used to find their prototype.

```py
from L import L

"""
L = [
"result = result & uVar4",
"bVar1 = ((tables[\"31fc1010\"])[input_e8[4]])",
"uVar2 = ((tables[\"320c1810\"])[bVar1])",
"uVar3 = tables[\"2b770150\"](uVar2)",
"bVar1 = ((tables[\"31fc1010\"])[input_118[15]])",
...
"""

# Parse L and extract the number of nested functions. The key is the address in tables
nested_functions = {}
for l in L:
    if "tables" in l:
        addr = l.split("[")[1].split("]")[0].strip("\"")
        
        # Count the number of [ and ( to determine the number of nested functions
        brackets = l.count("[")
        parentheses = l.count("(")
        # If "input" is in the string, -1 bracket
        if "input" in l:
            brackets -= 1
        if "uVar2" in l and parentheses==2:
            parentheses = 0
        nested_functions[addr] = parentheses
```

### Functions and tables generation

```py
def generate_table_simple(addr): # bVar1 = ((tables["2ca16010"])[input_108[13]])
    function_addrs = [get_bytes(addr+i*0x8, 0x8)[::-1] for i in range(0x100)]
    
    table = []
    for ival in function_addrs:
        value = execute_at(int(ival.hex(), 16), 0x10)
        table.append(value)
        if value > 0x100:
            print(f"WARNING: Simple function at {hex(int(ival.hex(), 16))} returned {value}")
    return table

def generate_table_double(addr): # uVar2 = ((tables["2cb16810"])[bVar1])
    function_addrs = [get_bytes(addr+i*0x8, 0x8)[::-1] for i in range(0x100)]

    table = []
    for ival in function_addrs:
        value = execute_at(int(ival.hex(), 16), 0x10)
        table.append(value)
        if value > 0x10000:
            print(f"WARNING: Double function at {hex(int(ival.hex(), 16))} returned {value}")
    if all([x < 0x100 for x in table]):
        print("WARNING: Double function seems to be simple")
    
    for i in range(0x100):
        is_mul = True
        for j in range(0x100):
            if table[j] != (i*j) % 0x10000:
                is_mul = False
        if is_mul:
            return lambda x: x*z3.BitVecVal(i, 16)
    print("Unknown function at address: ", hex(addr))
    return None


def genetate_function_simple(addr): # uVar3 = tables["00d35150"][uVar2]
    """
    Try a pattern on a few values, then returns a 1 input function like:
    lambda x + i; lambda x - i; lambda x * i; lambda -x + i; lambda -x - i etc. where i is a constant to be found
    """
    x = [i for i in range(0x100)]
    y = [execute_at(addr, i) % 0x10000 for i in x]
    
    for i in range(0x100):
        is_add = True
        is_sub = True
        is_mul = True
        is_rev_sub = True
        is_opp = True
        for j in range(0x100):
            if y[j] != (x[j]+i) % 0x10000:
                is_add = False
            if y[j] != (x[j]-i) % 0x10000:
                is_sub = False
            if y[j] != (x[j]*i) % 0x10000:
                is_mul = False
            if y[j] != (-x[j]+i) % 0x10000:
                is_rev_sub = False
            if y[j] != (-x[j]-i) % 0x10000:
                is_opp = False
        if is_add:
            return lambda x: x+z3.BitVecVal(i, 16)
        if is_sub:
            return lambda x: x-z3.BitVecVal(i, 16)
        if is_mul:
            return lambda x: x*z3.BitVecVal(i, 16)
        if is_rev_sub:
            return lambda x: -x+z3.BitVecVal(i, 16)
        if is_opp:
            return lambda x: -x-z3.BitVecVal(i, 16)
    print("Unknown function at address: ", hex(addr))
    return None
    
def generate_function_double(addr): # uVar3 = ((tables["2ca16810"])[uVar3])[uVar2]
    """
    Try a pattern on a few values, then returns a 2 input function like:
    lambda x,y: x+y; lambda x,y: x-y; lambda x,y: x*y; lambda x,y: -x+y etc.
    """
    function_addrs = [get_bytes(addr+i*0x8, 0x8)[::-1] for i in range(0x100)]
    
    table = []
    for ival in function_addrs:
        x = [i for i in range(0x100)]
        y = [execute_at(int(ival.hex(), 16), i) % 0x10000 for i in x]
        table.append(y)
    
    is_add = True
    is_sub = True
    is_mul = True
    is_rev_sub = True

    for i in range(0x100):
        for j in range(0x100):
            if table[i][j] != (i+j) % 0x10000:
                is_add = False
            if table[i][j] != (i-j) % 0x10000:
                is_sub = False
            if table[i][j] != (i*j) % 0x10000:
                is_mul = False
            if table[i][j] != (-i+j) % 0x10000:
                is_rev_sub = False
    if is_add:
        return lambda x,y: x+y
    if is_sub:
        return lambda x,y: x-y
    if is_mul:
        return lambda x,y: x*y
    if is_rev_sub:
        return lambda x,y: -x+y
    print("Unknown function at address: ", hex(addr))
    return None



def compute_target(addr, fast=False):
    result = -1
    initial_function_addrs = [(i,get_bytes(addr+i*0x8, 0x8)[::-1]) for i in range(0x10000)]
    for i,ival in initial_function_addrs:
        output = execute_at(int(ival.hex(), 16), 0x1)
        if output == 1:
            if result != -1:
                print(f"Multiple results found: {result} and {i}")
            result = i
            if fast:
                break
    return result

tables_values = {}
for addr in tqdm.tqdm(nested_functions.keys()):
    if nested_functions[addr] == 0:
        tables_values[addr] = generate_table_double(int(addr, 16))
    elif nested_functions[addr] == 1:
        tables_values[addr] = genetate_function_simple(int(addr, 16))
    elif nested_functions[addr] == 2:
        tables_values[addr] = generate_table_simple(int(addr, 16))
    elif nested_functions[addr] == 3:
        tables_values[addr] = generate_function_double(int(addr, 16))
    else:
        print(f"Nested functions: {nested_functions[addr]} not supported")
```

### Z3 solving

[`conditions.py`](./_Files/conditions.py) contains the function `generate_conditions` which generates the conditions for the Z3 solver.

```py
from conditions import generate_conditions

s = z3.Solver()

z3_tables = {}
for key in tqdm.tqdm(tables_values.keys()):
    try:
        if nested_functions[key] == 0: # Table with values 8 -> 16
            z3_tables[key] = tables_values[key] # Function
        elif nested_functions[key] == 1: # Simple function
            z3_tables[key] = tables_values[key]
        elif nested_functions[key] == 2: # Table with values 8 -> 8
            z3_tables[key] = z3.Array(f"table_{key}", z3.BitVecSort(8), z3.BitVecSort(16))
            for i in range(0x100):
                s.add(z3_tables[key][z3.BitVecVal(i, 8)] == z3.BitVecVal(tables_values[key][i], 16))
        elif nested_functions[key] == 3: # Double function
            z3_tables[key] = tables_values[key] # Function
        else:
            print(f"Nested functions: {nested_functions[key]} not supported")

    except:
        print(f"Error with key: {key}")
        raise



input = [z3.BitVec(f"input_{i}", 8) for i in range(0x40)]

for i in range(0x40):
    s.add(input[i] >= 0x20)
    s.add(input[i] < 0x7f)

s.add(input[0] == ord("E"))
s.add(input[1] == ord("C"))
s.add(input[2] == ord("W"))
s.add(input[3] == ord("{"))
s.add(input[0x3f] == ord("}"))

input1 = input[:0x10]
input2 = input[0x10:0x20]
input3 = input[0x20:0x30]
input4 = input[0x30:0x40]

conditions, target_addrs = generate_conditions(z3_tables, input1, input2, input3, input4)

target_values = []
for target in tqdm.tqdm(target_addrs):
    target_values.append(compute_target(int(target, 16), fast=True))

for i in tqdm.tqdm(range(len(conditions))):
    s.add(conditions[i] == target_values[i])

print("Checking ...")
print(s.check())

m = s.model()
output = ""
for i in range(0x40):
    output += chr(m[input[i]].as_long())
print(output)
```

```sh
sat
ECW{3V3n_1nD1r3c1_c411S_AnD_M1lL10N_FUnC110ns_CaNn0T_5t0P_4_Pr0}
```