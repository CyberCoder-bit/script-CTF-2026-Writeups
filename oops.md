# Crypto/oops Writeup

Oops
443
NoobMaster

I am from the future! I accidentally forgot to link chall.zip! Surely you can find it and solve it right?

## Solution:


**Step 1:**
First, we need to find the chall file... Looking at misdirection's link I see https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Misdirection/enc.txt. Replace the chall name with Oops and chall file with chall.zip and you get the file at [https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip](https://scriptctf-2026-wave1-randomchars-4f7d3a6b.s3.us-east-1.amazonaws.com/Crypto/Oops/chall.zip).


**Step 2:**
Looking at chall.zip and unzipping it, we see it is AES-256 ECB, which should be very difficult to brute force:
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

But luckily, the challenge author has left us a hint after the code: ```random.seed(int(time.time()))```. This likely means we will have to find the seed. But brute forcing the time without any information would take too long, so instead we look at the file metadata using ```unzip -Z -v```, which gives the zip metadata.
Since Python's random is deterministic, if we can get the seed from the metadata, we can get the key.

**Step 3:**

Trimmed Output:
```
unzip -Z -v chall.zip
Archive:  chall.zip
There is no zipfile comment.

End-of-central-directory record:
-------------------------------

  Zip archive file size:                       629 (0000000000000275h)
  Actual end-cent-dir record offset:           607 (000000000000025Fh)
  Expected end-cent-dir record offset:         607 (000000000000025Fh)
  (based on the length of the central directory and its expected offset)

  This zipfile constitutes the sole disk of a single-part archive; its
  central directory contains 2 entries.
  The central directory is 155 (000000000000009Bh) bytes long,
  and its (expected) offset in bytes from the beginning of the zipfile
  is 452 (00000000000001C4h).


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

Looking at the output, we can see the timestamps! We can get the flag by decoding using the ciphertext from enc.txt and the key we get from the metadata date/time! The hint says, ```# Preserves upto the MINUTE, not seconds ;)```, meaning the time is likely rounded to the minute. Looking at the files, the timestamp is likely ```2069 Nov 30 11:39:00 UTC``` since it doesn't have the seconds instead of ```2026 Aug 4 11:55:41 UTC``` which does.
Additionally, the ```enc.txt``` timestamp is in the future, making it more suspicious and the likely timestamp.
Unfortunately, since the metadata only gives us the minute (as hinted to), we need to brute-force the time, but since there are only 60 possibilities, it should be done fairly quickly.

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

Using the script it gives the flag: **scriptCTF{mY_buck37_1s_l34k1ng!}**

## Summary:
1. Find link by modifying url from other challenges
2. Interpret hint and notice vulnerability of reversible seed/key
3. Get zip metadata
4. Brute force the second and decrypt to get flag
