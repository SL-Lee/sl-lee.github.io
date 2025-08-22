---
Created: 2025-08-22T11:34:47
---
# Welcome

## Insanity Check

> [!info] Challenge Descripion
> No way! There's more?!?
>
> THIS IS DRIVING ME INSAAAANNNNEEEEEEEEEEEEEE

There was a similarly-named beginner challenge called "Sanity Check" where one simply runs `nc challs.nusgreyhats.org 33000` to obtain the flag. Seeing as they are similarly-named, they must be related to each other (the challenge description doesn't really provide any new information).

After staring at the output for a while, I noticed there was a large seemingly-empty gap between the prompt and the actual output (the banner and flag):

![[../images/insanity-check-abnormal-whitespace-gap.png]]

This raised a suspicion that some information could be encoded in the [Whitespace Language](https://www.dcode.fr/whitespace-language) and hiding in plain sight. I fired up Wireshark and captured the data received by running `nc challs.nusgreyhats.org 33000` and noticed that indeed, it was a mix of `0x20` (space), `0x09` (tab) and `0x0a` (line feed) bytes. I selected all the bytes from the beginning of the file and the first byte that is not any of the 3 aforementioned whitespace characters into a file named `whitespace.ws`:

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

So there is a hint that the flag is in Base64. However, none of the files in the zip file contains the flag. Thinking that this ZIP file must have been altered somehow, I opened this file in ImHex and parsed it with the ZIP compression archive pattern (`zip.hexpat`), and noticed that at the end, there is a payload at the end of the file that wasn't parsed by ImHex:

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

I read up on the PNG file format and attempted to analyze the raw pixel data:

- PNG has a header chunk (`IHDR` that describes the image's width and height, and **pixel color type** - two common ones are **RGB triple** (mapped to `0x02`) and **RGBA** (mapped to `0x06`))
- They are then followed by other chunk types, but the most prominent one is `IDAT`, which contains the compressed pixel data

I concatenated all the compressed data and decompressed it myself to get the raw pixel data. From the pixel values, it can be observed that, after the row filter type byte `0x01`, the byte `0x00` occurs every **4** bytes, suggesting that each pixel actually uses 4 bytes of storage space.

![[../images/cosmic-bitflip-raw-pixel-data.png]]

By changing the `IHDR.color_type` field from `0x02` (`RGBTriple`) to `0x06` (`RGBA`) and saving it to a new PNG file, I was able to recover the "uncorrupted" image:

![[../images/cosmic-bitflip-recovered-flag.png]]

> [!success] Flag
> `flag{b1t_fl1p_m4d3_my_fl4g_tr4nsp4r3n7}`

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

# Rev

## Whats In The Bag 🍼

> [!info] Challenge Description
> Find out how to make a bag, and what to put in it!

## Flag Checker Baby 🍼

> [!info] Challenge Description
> Flag checker is kinda hard so I made an easier version of it!
> 
> p.s. `welcome-ctf-ida-guide.zip` might be helpful if you're new to reverse engineering!

## Flag Checker

> [!info] Challenge Description
> A simple flag checker... wait... I can't run it??!?

## Wannaflag

> [!info] Challenge Description
> I downloaded this cool program my friend sent me, he told me it would add some cool ascii art to my flag file. However, after running the program, it seems like my flag.txt file is encrypted! What can I do?

## Organised Person

> [!info] Challenge Description
> I love to organise my stuff by packing them! But i forgot the password for this file ;-;

# Misc

## Crazy Gifarfe

> [!info] Challenge Description
> OMG that's some ccrrraaaazzyyy GIFARFES, no way those necks don't hurt

## Ads

> [!info] Challenge Description
> What does ADS stand for again? Was it Alternate Data Shift? Or was it Alternate Data Spectrogram? Hmm... whatever. Here is a file containing my secrets. Try to uncover them if you can.
> 
> Extract the provided file using WinRAR with administrator privileges.

## Nus Geographer

> [!info] Challenge Description
> Bluey decided to take a walk around NUS before school starts. He wrote down some lines in his diary for Pinky to follow. Can you figure out the message to Pinky?
> 
> The flag format is: `grey{THE_FLAG_IN_UPPERCASE_AND_UNDERSCORE_ONLY}`
> 
> Note: Do not brute force any APIs. When in doubt, maybe the dates can help you.

