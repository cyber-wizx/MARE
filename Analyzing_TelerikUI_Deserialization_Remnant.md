# Tools
PeStudio -> https://www.winitor.com/download

Dcode -> https://www.digital-detective.net/dcode/

IDA Free -> https://hex-rays.com/ida-free/

## Static Analysis
1. Filename itself indicates a date/time value in unix format. Decoding the filename gives 2020-05-13 01:48:36 UTC

![image](https://user-images.githubusercontent.com/87561308/126115720-54e9a1f7-98d9-44ce-b682-a37e26acc047.png)

2. In PeStudio, we observed an Internet IP address, **_WS2_32.dll_** library together with **_WSAConnect_** and **_WSASocket_** function which could signify that the connection to the IP address. A reverse shell dll was also seen.

![image](https://user-images.githubusercontent.com/87561308/126421640-bbdda5e4-f767-449b-808e-f1e295b7bd31.png)

## Debugging

### IDA-FREE
1. Load the file into Idafree, and search for the **_WSAConnect_** function in "Import" module, double-click to bring you to the code view where **_WSAConnect_** is initializaed.

![image](https://user-images.githubusercontent.com/87561308/126118539-81c2a0db-3110-4496-8722-64d537cc7578.png)

2. Right-click on **_WSAConnect_** and "Jump to XRef to Operand", you will a pop up table for all addresses where **_WSAConnect_** is called.

![image](https://user-images.githubusercontent.com/87561308/126120733-9070a881-0464-468d-b101-e1cac609323b.png)

3. Selecting the entry will bring you to the code view where **_WSAConnect_** is called.

![image](https://user-images.githubusercontent.com/87561308/126118373-76e08310-0385-4135-8b90-0f13c8fde5a9.png)

4. Observed the block of assembly, and you will find (1) static IP being declared earlier.

![image](https://user-images.githubusercontent.com/87561308/126421974-5359621f-a904-4c87-941f-183265dd3edb.png)

5. **_htons_** is a function in **_WS2_32.dll_** library that takes in a 16-bit number in host byte order and returns a 16-bit number in network byte order used in TCP/IP networks. The value of 3995h yields the value "14741" in decimals.

![image](https://user-images.githubusercontent.com/87561308/126422414-ae4d6b25-e1cf-492c-bae2-51d99cbe6dbe.png)

6. From the above, we are quite confident that there is a logic in the dll performing a reverse shell to the IP over port 14741.

# Reference
https://labs.bishopfox.com/tech-blog/cve-2019-18935-remote-code-execution-in-telerik-ui
