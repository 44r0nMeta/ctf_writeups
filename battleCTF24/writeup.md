# AFRICA BATTLE CTF 2024 PREQUAL

#### Challenges:
- Rules (Misc)
- Invite Code (Misc)
- Do[ro x2] (Forensics)
- Poj(Pwn)
- Jenkins
- Hmmmm!... (Web): _But not submitted, cause time over_

## Rules (Misc)
![image](./assets/1.png)

```
Flag: battleCTF{HereWeGo}
```
## Invite Code (Misc)

The challenge in question was made available before the CTF event started and can be found on bug|pwn Discord, Twitter and LinkedIn.

![image](./assets/2.png)
![image](./assets/3.png)

Decode the hex use *invite.ini* content and decode as b64 and extract gzip archive
![image](./assets/4.png)

Now we crack the user pasword using john and rockyou wordlist and find password **nohara**

![image](./assets/5.png)

At this point we use cracked password as key to decrypt RC4 encryption and got the flag

![image](./assets/6.png)

```
Flag: battleCTF{pwn2live_d7c51d9effacfe021fa0246e031c63e9116d8366875555771349d96c2cf0a60b}
```


