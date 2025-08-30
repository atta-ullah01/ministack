## Ministack: A Minimal TCP/IP Stack

Ministack is a lightweight, educational TCP/IP stack written in C. It is designed to be a simple and understandable implementation of the core networking protocols, perfect for learning about network programming and protocol design from the ground up.

This stack implements the fundamental layers of the TCP/IP model:

    Application Layer: Basic TCP client and server examples.
    Transport Layer:
        TCP (Transmission Control Protocol)
        UDP (User Datagram Protocol)
	
    Network Layer:
        IPv4 (Internet Protocol version 4)
        ICMP (Internet Control Message Protocol) for handling pings and network diagnostics.
        ARP (Address Resolution Protocol) for resolving IP addresses to MAC addresses.
	
    Link Layer & Drivers:
        Ethernet II framing.
        Virtual Network Device Drivers:
            TAP Driver (eth_tap): Allows the stack to communicate with the host OS network.
            Loopback (loopback): A virtual interface for local network communication (127.0.0.1).

### Building the Stack
Prerequisites, ensure you have the following installed:
- gcc (or any C compiler)
- make
- The ability to create TUN/TAP interfaces on your system (usually via ip tuntap).


### Compilation

To compile the entire project, simply run the `make` command from the root directory:
```
make
```
This will compile all source files and place the final executables in the `bin/` directory.

To clean up the build artifacts, run:
```
make clean
```

### How to Run

The stack uses a TAP interface to connect to the host machine's network. The following steps will guide you through setting it up and running the test applications.
#### 1. Setup the TAP Interface

First, create and configure a TAP interface on your host machine. The stack is configured in `test/test.h` to use `192.0.2.2`, so we will set up the host's end of the virtual link to be `192.0.2.1`.

```
# Create the TAP interface named "tap0" and assign it to your user
sudo ip tuntap add dev tap0 mode tap user $(whoami)

# Bring the interface up
sudo ip link set dev tap0 up

# Assign an IP address. This will be the gateway for our stack.
sudo ip addr add 192.0.2.1/24 dev tap0
```

#### 2. Testing

###### Scenario A: Testing the Ministack Server

Now, you can run the TCP server. It will listen for connections on the IP address configured for the stack's TAP interface (`192.0.2.2`).

- **Terminal 1: Run the Ministack Server** Start the `tcp_server` application. It will bind to the stack's TAP interface IP (`192.0.2.2`) and wait for connections on port `12345`. 
	```
		# Usage: ./bin/tcp_server [listen_addr] listen_port
		./bin/tcp_server 192.0.2.2 12345
	```


- **Terminal 2: Connect with a `netcat` Client** In a new terminal, use `netcat` (`nc`) on your host OS to connect to the Ministack server.
    ```
	    nc 192.0.2.2 12345
    ```
	
	Now, type a message like "Hello world!" in netcat and press Enter.


##### Scenario B: Testing the Ministack Client

Now, let's reverse the roles. We will run a `netcat` server on the host OS and connect to it using the Ministack client.

- **Terminal 1: Run the `netcat` Server** Start `netcat` in listen (`-l`) mode on your host, waiting for a connection on port `54321`.
    ```
	    # Listen for incoming connections on port 54321
	    nc -l -p 54321
    ```
    
- **Terminal 2: Run the Ministack Client** In a new terminal, run the `tcp_client` and tell it to connect to the host's IP (`192.0.2.1`) where `netcat` is listening.
    ```
	    # Usage: ./bin/tcp_client foreign_addr:port
	    ./bin/tcp_client 192.0.2.1:54321
    ```
    
The client will establish a connection. Now, you can type a message like `Hello from the client!` in this terminal and press Enter. You will see the text appear in the `netcat` server window in Terminal 1.

