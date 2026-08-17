# Misc/Golf? Writeup

Title: Golf?

483

Author: Connor Chang

Description: my lil bro wanted to put a spiral in his picture frame but it only has 250px

Attachments
server.py
nc challs.scriptsorcerers.xyz 10501


## Solution:

**Step 1:**

First, we can inspect server.py. At first glance, this seems like a [code golf challenge](https://code.golf/), meaning we will have to use as few characters as possible to print:
```python
goal =  [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [35, 36, 37, 38, 39, 40, 41, 42, 43, 10],
        [34, 63, 64, 65, 66, 67, 68, 69, 44, 11],
        [33, 62, 83, 84, 85, 86, 87, 70, 45, 12],
        [32, 61, 82, 95, 96, 97, 88, 71, 46, 13],
        [31, 60, 81, 94, 99, 98, 89, 72, 47, 14],
        [30, 59, 80, 93, 92, 91, 90, 73, 48, 15],
        [29, 58, 79, 78, 77, 76, 75, 74, 49, 16],
        [28, 57, 56, 55, 54, 53, 52, 51, 50, 17],
        [27, 26, 25, 24, 23, 22, 21, 20, 19, 18]]
```

Essentially, we want to submit code that prints this while staying under the size limit in order to get the flag.

**Step 2:**

So first I tried to make a very compact algorithm to solve this challenge. I looked at [Stack Overflow](https://stackoverflow.com/questions/46671637/two-dimensional-array-in-python) and got the code:
```
# Source - https://stackoverflow.com/q/46671637
# Posted by John Snow, modified by community. See post 'Timeline' for change history
# Retrieved 2026-08-10, License - CC BY-SA 3.0

def createSpiralMatrix(n):
    dirs = [(-1, 0), (0, -1), (1, 0), (0, 1)]
    curDir = 0
    curPos = (n - 1, n - 1)
    res = [[0 for item in range(n)] for sublist in range(n)]

    for i in range(1, n * n + 1):
        res[curPos[0]][curPos[1]] = i
        nextPos = curPos[0] + dirs[curDir][0], curPos[1] + dirs[curDir][1]
        if not (0 <= nextPos[0] < n and
                0 <= nextPos[1] < n and
                res[nextPos[0]][nextPos[1]] == 0):
            curDir = (curDir + 1) % 4
            nextPos = curPos[0] + dirs[curDir][0], curPos[1] + dirs[curDir][1]
        curPos = nextPos

    return res
```
This code basically rotates the direction in a clockwise fashion if we have already filled the grid we are going to or if it becomes out of bounds.
Then I tried to compact the code and change the range from 1-n^2 to 0-99. I also made all the variables one letter and removed all spaces. I also split curPos to separate x and y variables and nextPos to X, Y.

Variable Mappings
D: dirs
d: curDir
x,y: curPos
X,Y: nextPos
r: res

```
D=[(-1,0),(0,-1),(1,0),(0,1)]
d=x=y=9
r=[[-1]*10 for _ in range(10)]
for i in range(100):
    r[x][y]=i
    X,Y=x+D[d][0],y+D[d][1]
    if not(0<=X<10 and 0<=Y<10)or r[X][Y]>=0:
        d=(d+1)%4
        X,Y=x+D[d][0],y+D[d][1]
    x,y=X,Y
for a in r:
    print(*a)
```

**Step 3:**

But when I ran it locally against server.py, it was rejected:
```
$ ~/script$ python3 server.py
Send python code (enter EOF when done):
D=[(-1,0),(0,-1),(1,0),(0,1)]
d=x=y=9
r=[[-1]*10 for _ in range(10)]
for i in range(100):
    r[x][y]=i
    X,Y=x+D[d][0],y+D[d][1]
    if not(0<=X<10 and 0<=Y<10)or r[X][Y]>=0:
        d=(d+1)%4
        X,Y=x+D[d][0],y+D[d][1]
    x,y=X,Y
for a in r:
    print(*a)
EOF
TOO LONG
```

To see how much we need to compact, I added ```print(font.getlength(code))```.
```
print(font.getlength(code))
if font.getlength(code) > 380:
    return "TOO LONG"
```

After rerunning the code, I get: ```1055.90625```

The required value is 380 or less, which is pretty far off, meaning I will have to shorten my code by around 3 times.

**Step 4:** 

At this point, I was ready to give up. But there was one feature that I noticed was different compared to standard code-golf challenges. Usually, we count the number of characters.
But here, we count the length of the text in ```font.getlength(code) > 380``` using Pillow. In addition, in the challenge description it says ```250px```, possibly hinting that the vulnerability was here.

After this, I did some research and found some [Pillow Documentation](https://pillow.readthedocs.io/en/stable/reference/ImageFont.html#PIL.ImageFont.ImageFont.getlength) which said ```font.getlength()``` got the length the text was supposed to be offset by, or the advance width. After doing a bit more research and looking at an [article](https://freetype.org/freetype2/docs/glyphs/glyphs-3.html), I realized that Unicode combining characters could be used to make the length really small since they are usually rendered on top of or around a preceding character and have zero or near-zero advance width.
An example would be accents or marks, which are normally on top of a character and therefore count as almost no advance width when rendered. This can still work in Python because Python treats them as separate characters. By using this technique, we can make a long Python string occupy very little space.

**Step 5:**

After this, I researched common mark ranges and found that ```U+0300–U+036F``` was a standard range for these accents/marks. Therefore, we can add 0x300 or 768 in decimal to the Unicode value of each character. Since the text we are encoding is only digits, spaces, and newlines, then adding 0x300 will land in the Combining Marks Range.

Instead of writing an actual script, we just encode the exact 10x10 textual representation and decode/print it with ```;print(''.join(chr(ord(c)-768)for c in s))```. I wrote a script that just encodes the matrix into Unicode values + 768 and decodes it when running. 
Normally, hardcoding 100 values would be much larger than writing an algorithm, but since most of the numbers/spaces can be represented with zero or near-zero advance width, hardcoding becomes much cheaper. The final payload becomes: ```s='<encoded combining characters>';print(''.join(chr(ord(c)-768)for c in s))```.

Final script:
```
from pwn import *

HOST = "challs.scriptsorcerers.xyz"
PORT = 10501

goal = [
    [0,1,2,3,4,5,6,7,8,9],
    [35,36,37,38,39,40,41,42,43,10],
    [34,63,64,65,66,67,68,69,44,11],
    [33,62,83,84,85,86,87,70,45,12],
    [32,61,82,95,96,97,88,71,46,13],
    [31,60,81,94,99,98,89,72,47,14],
    [30,59,80,93,92,91,90,73,48,15],
    [29,58,79,78,77,76,75,74,49,16],
    [28,57,56,55,54,53,52,51,50,17],
    [27,26,25,24,23,22,21,20,19,18]
]

text = "\n".join(" ".join(map(str, row)) for row in goal)

enc = "".join(chr(768 + ord(c)) for c in text)

code = "s='" + enc + "';print(''.join(chr(ord(c)-768)for c in s))"

print("payload characters:", len(code))

io = remote(HOST, PORT)
io.recvuntil(b"EOF when done):\n")

io.sendline(code.encode("utf-8"))
io.sendline(b"EOF")

print(io.recvall().decode(errors="replace"))
```

Flag: **scriptCTF{8u7_1_c@n7_s3e_7h3_c0d3}**

## Summary:

1. Recon and identify the constraint that it has to be a certain size
2. Try to make compact code
3. Understand it is infeasible to achieve the required length
4. Research how length is measured and how Unicode combining characters bypass the length cap
5. Run the final script and get the flag
