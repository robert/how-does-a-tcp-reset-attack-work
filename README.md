# How does a TCP Reset Attack work?

The supporting code for my blog post "[How does a TCP Reset Attack work?](https://robertheaton.com/2020/04/27/how-does-a-tcp-reset-attack-work/)"

## To run

Pre-requisites: [install ncat](https://nmap.org/ncat/). Comes pre-installed on OSX.

1. Install dependencies: `virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`
2. Setup TCP connection. In one terminal window run `nc -nvl 8000` to set up a server
3. In another terminal window run `nc 127.0.0.1 8000` to connect to the server
4. In a third window run `python3 main.py` to run our sniffing program
5. Type into one of the TCP connection windows. You should see the sniffing program log some output, send a `RST` packet, and the `nc` connection should be broken
