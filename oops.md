# Crypto/oops Writeup

Oops
443
NoobMaster

I am from the future! I accidentally forgot to link chall.zip! Surely you can find it and solve it right?

## Solution:


**Step 1:**
First, we need to recover the missing challenge file. Looking at the link of the ```Misdirection``` challenge I see https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Misdirection/enc.txt. Replacing ```Misdirection/enc.txt``` with ```Oops/chall.zip``` gives you the file at [https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip](https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip).


**Step 2:**
Looking at chall.zip and unzipping it, we see it is AES-256-ECB. Since the key is 256 bits, brute-forcing the key should usually be infeasible:
```python
import random
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

flag = open('flag.txt','rb').read()

random.seed(int(time.time())) # Preserves upto the MINUTE, not seconds ;)
key = random.randbytes(32)

cipher = AES.new(key, AES.MODE_ECB)

enc = cipher.encrypt(pad(flag,16)).hex()

open('enc.txt', 'w').write(enc)
```

But luckily, the challenge author has left us a hint after the code: ```random.seed(int(time.time()))```. This likely means we will have to find the seed. But brute-forcing the time without any information would take too long, so instead we look at the file metadata using ```unzip -Z -v```, which gives the zip metadata.
Since Python's ```random``` module is deterministic, if we can get the seed from the metadata, we can recover the key.

**Step 3:**

Trimmed Output:
```
unzip -Z -v chall.zip
...

Central directory entry #1:
---------------------------

  chall.py

  ...

  file last modified on (UT extra field modtime): 2026 Aug 4 11:55:41 UTC

  ...

Central directory entry #2:
---------------------------

  enc.txt

  ...

  file last modified on (UT extra field modtime): 2069 Nov 30 11:39:00 UTC

  ...

```

**Step 4:**

Looking at the output, we can see the timestamps! We can get the flag by decoding using the ciphertext from enc.txt and the key we get from the metadata date/time! The hint says, ```# Preserves upto the MINUTE, not seconds ;)```, meaning the time is likely rounded to the minute in the ZIP metadata. Looking at the files, the timestamp is likely ```2069 Nov 30 11:39:00 UTC``` since it is rounded to the minute, instead of ```2026 Aug 4 11:55:41 UTC``` which is not.
Additionally, the ```enc.txt``` timestamp is in the future, which matches the challenge description of ```I am from the future!```.
Since the metadata only gives us the minute (as hinted at), we need to brute-force the time, but since there are only 60 possibilities, it should be done fairly quickly.

Here is a script:

```python
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timezone

enc = bytes.fromhex("d37cbce47f0c71a75d644badb77039e48ab1645f60ddebe928c0a3c417561345b4852636ecb388ec79417357100da120")

t = int(datetime(2069,11,30,11,39,0,tzinfo=timezone.utc).timestamp())

for i in range(60):
    s = t+i
    random.seed(s)
    k = random.randbytes(32)

    c = AES.new(k,AES.MODE_ECB)
    x = c.decrypt(enc)

    try:
        x = unpad(x,16)
        if b"scriptCTF{" in x:
            print(s)
            print(x)
            break
    except:
        pass

```

Using the script, it gives the flag: **scriptCTF{mY_buck37_1s_l34k1ng!}**

## Summary:
1. Find the link to ```chall.zip``` by modifying the URL from other challenges.
2. Interpret the hint and notice the AES key is generated deterministically from ```random.seed(int(time.time()))```.
3. Get ZIP metadata.
4. Brute-force the 60 possible seconds within the minute and decrypt to get the flag: **scriptCTF{mY_buck37_1s_l34k1ng!}**.
