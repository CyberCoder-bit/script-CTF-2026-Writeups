# Rev/Diabolical Writeup

Title: Diabolical

Author: Noobmaster

Description:

"scriptCTF does not have hard reversing challenges" - Armored Pawn

Let's see about that shall we?

Attachments:
vault

## Solution:

**Step 1:**

I first opened `vault` up in IDA Free and allowed it to analyze it. Since the binary looked very complicated and there were many functions and strings related to cryptography.

Before reversing the checking algorithm, I decided to check the IDA Strings subview.

**Step 2:**

When I opened up the IDA Strings subview, I searched through the strings, and the last one looked like a base64-encoded string.

<img width="2557" height="1121" alt="image" src="https://github.com/user-attachments/assets/451bc8fe-db6f-4880-b450-e99ac9e2e17a" />

The last value was `c2NyaXB0Q1RGe24wdF9zMF9oNHJkXzRmdDNyXzRsbH0=`. 

**Step 3:**

Next, I base64 decoded with [base64decode.org](https://www.base64decode.org/) (you can also do ```echo 'c2NyaXB0Q1RGe24wdF9zMF9oNHJkXzRmdDNyXzRsbH0=' | base64 -d```). Then, I get the flag: **scriptCTF{n0t_s0_h4rd_4ft3r_4ll}**.

## Summary
1. Open `vault` file in IDA Free.
2. Notice the suspicious string at the very end.
3. Base64 decode and get the flag: **scriptCTF{n0t_s0_h4rd_4ft3r_4ll}**.
