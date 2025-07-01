## 1️⃣ Networking Fundamentals

- **OSI & TCP/IP models**: Learn the **7 OSI layers and 4 TCP/IP layers**, packet flow, and PDUs.

- **IP addressing & Subnetting**: Practice CIDR notation and subnet masks (i.e., /24, /26).

- **Common protocols & ports**: HTTP(80/443), DNS, SMTP/POP3/IMAP, SSH(22), FTP/Telnet, RDP(3389), ARP, ICMP (“ping”), traceroute.

- **Packet structure**: Learn TCP vs UDP headers and packet anatomy.

- **NAT, VPN, VLAN basics**: Understand how networks segment, mask, and tunnel traffic.





OSI model consist of 7 Layers, Application, Presentation, Session, Transport, Network, Data 
	link, Physical. 
Application layer is the interface, the user uses to interfere with. It provides servicess like     
	browsing, email, file transfer.
Presentation layer is responsible for formatting data. It deals with encryption, decryption 
	and sometimes compression of data.
	for example, converting plain text into UTF-8, TLS/SSL encryption
Session Layer is used to keep track of a user using cookies or session ids, or maintaing 
	connection during video calls.
Transport Layer is responsible for how data is transferred. It might use TCP/IP or sometimes 
	UDP. THese 2 are the protocols used to transfer data.
		TCP/IP is reliable but little extra time consuming,
		UDP is unreliable but it is very fast.
		TCP/IP sacrifices speed for reliability and UDP sacrifices reliability for speed.
Network layer is responsible for routing data across the network based on IP addresses. 
	Also deals with NAT, Subnet, Packet forwarding.
Data Link layer Deals with MAC address, Switches. Also deals with ARP.
Physical layer is responsible for transferring data using ethernet cables, wifi.


TCP/IP :
	TCP/IP is one of the transport protocol used to transfer data.
	This is a connection-oriented transport protocol that ensures reliable and ordered delivery of packet.
	Here, before transmitting data, client and server makes 3 way handshake.
	During 3 way handshake, the client sends a SYN request, SEQ to server for which server responds with SYN-ACK(client SEQ + 1) as well as its own SEQ. Again the client responds back with ACK(server SEQ + 1). Now, both client and server are ready to transfer data in between. 
	Each packet has:
		SEQ to keep track the order
		ACK to acknowledge what's received.
	All the packets are delivered
	Packets are in order.
	Lost or corrupted packets are retransmitted.
	
UDP :
	Unlike TCP, UDP doesn't have 3 way handshake mechanism to ensure all the packets are delivered or received. As soon as the connection is established packet gets transimitted regardless of other packets.
		Faster compared to TCP/IP
		Ideal for real time applications
			Video calls, Online games

ARP:
	is a protocol that is used to resolve IP address to MAC address on a local network
	When a device needs to send data to another device, it broadcasts ARP request, for which device owning that IP address replies back its MAC address.
		happens at Layer 2
NAT:
	is used by routers to translate private IP address into public IP address. This allows multiple devices to use single gateway / public address to access internet.
		happens at Layer 3
	


HTTP
	 is a protocol used by web browsers and servers to communicate and exchange data like html pages,images, videos, etc.
		 It's default port is 80, and it uses TCP/IP
		 data is sent as plain text
HTTPS
	is http protocol having additional security features using SSL, TLS
	default port is 443
	data is encrypted

	SSL/TLS:
	Client sends a `ClientHello` message to the server. This `ClientHello`
	contains information about the browser such as the supported TLS versions, a
	list of supported encryption algorithms (cipher suites), compression methods,
	and a random value used for key generation. The server responds with a
	`ServerHello` message and its digital certificate (called a leaf 
	certificate), which is issued by an intermediate certificate authority such
	as Entrust, GeoTrust, or Cloudflare. This certificate includes the server’s
	public key and a digital signature, which is the result of signing the
	certificate’s contents (including the server’s public key) using the
	intermediate CA’s private key. The client verifies the certificate by
	decrypting the signature using the intermediate CA’s public key to ensure it
	hasn't been tampered with, validating the certificate chain up to a trusted
	root CA, and checking that the certificate's domain matches the server’s
	hostname. If all these checks pass, the client trusts the server’s identity.
	
	Next, the key exchange process begins using Elliptic Curve Diffie-Hellman
	(ECDH). Each side—client and server—generates a private key and then computes
	a corresponding public key using a predefined base point `G` on an elliptic
	curve (such as X25519 or secp256r1). The client’s public key is `A = a × G`
	and the server’s public key is `B = b × G`, where `a` and `b` are their
	respective private keys. Both sides exchange their public keys and then
	compute the same shared secret: the client computes `S = a × B` and the
	server computes `S = b × A`, both resulting in `S = ab × G`. This shared
	secret is then used as input to a key derivation function (HKDF) to produce a
	symmetric encryption key.
	
	Even if a malicious actor intercepts the traffic, they cannot compute the
	shared secret because they only see the public keys `A` and `B` and not the 
	private keys `a` or `b`. Calculating the private key from a public key on
	anelliptic curve is computationally infeasible due to the Elliptic Curve
	Discrete Logarithm Problem. Without access to the shared secret, the attacker
	cannot derive the symmetric key, making it impossible to decrypt or tamper
	with the communication. This ensures the confidentiality and integrity of the
	data transmitted between client and server.


DNS:
	Acts like a internet phone-book which resolves human readable domain name with its IP address. Uses port 53
	Types:
		Recursive resolvers: Queries other DNS server to fecth right domain IP address
		Root nameservers: Directly queries to the right TLD domain name servers based on domain extensions
		TLD nameservers: handles queries for specific domain extensions(.in , .org, etc) and point to authoritative name servers.
		Authoritative nameservers:  Stores actual domain IP address and returns final
		corresponding IP address

SMTP:
		is an application layer protocol used to send, relay, forward email between email client and servers or two email servers.
		Uses 25 port by default
		SMTPS(465)
		SMTP/TLS(587)

		POP3:          Post Office Protocol
			POP3 is a simple protocol to download emails from the server 
			to the local machine.
			Once downloaded from server, emails are most probably deleted
			from email servers.
		IMAP:          Internet Message Access Protocol
			is a protocol used for centralized management of emails
			Everything is backed up.
			Has become default standard for modern email servers
	
SSH: Secure Shell / 22
	is a network protocol that provides secure access to remote computer over an unsecured network.
	Uses Asymettric encryption for initial handshake, after authentication all data is encrypted using shared session key.

Proxing:
	act of routing traffic through another server
	2 types:
		Forward proxy: client->proxy server->actual server  
			:To visit regionally banned sites]
		Reverse proxy: client -> actual server -> internal server
			:Used for load balancing in web servers
SOCKS5:
	is a protocol-level proxy that forwards any kind of traffic without modifying it, doesn't encrypt it, but gives you IP masking, app-specific routing, DNS tunneling, and firewall evasion.
		   Used by Developers for scraping data
		   App-specific privacy (e.g., torrent apps)
		   Low-latency, flexible traffic rerouting

DNS Tunneling:
**DNS tunneling is the practice of encoding data (commands, files, login info) inside DNS queries and responses**, turning the DNS protocol into a data transmission channel.


How to Detect DNS Tunneling:
Good SOC (Security Operations Center) practices look for:

| Indicator                              | Why it’s Suspicious                        |
| -------------------------------------- | ------------------------------------------ |
| High number of DNS requests per second | Tunnels break files into many small chunks |
| Long subdomain lengths                 | Encoded data increases domain length       |
| Unusual TLDs or domains                | Like `.xyz`, `.tk`, `.cn`, etc.            |
| Repeated lookups to same domain        | Used for constant contact with attacker    |
| DNS over non-standard ports            | Might be trying to avoid detection         |

VLAN:
	is a logical subdivision of a physical network that allows devices to be grouped into separate **broadcast domains** at **Layer 2** (Data Link layer). Devices in different VLANs cannot communicate directly, even if connected to the same switch — communication between VLANs requires a **router** or **Layer 3 switch**. VLANs isolate traffic based on **MAC addresses**, and are configured using **VLAN IDs** on switches.
Subnet:
	is a logical segmentation of an IP network at **Layer 3** (Network layer), defined using **IP addresses and subnet masks (CIDR)**. Devices in different subnets are on different **IP broadcast domains**, and require a **router** for inter-subnet communication. Subnets isolate traffic at the **IP level**, and are typically used by **routers** to organize and route network traffic efficiently.

Telnet:
	is a protocol used to access remote computers or servers over TCP/IP protocol.
		Transmitted data in plain text.
		Problems:
			Doesn't have Encryption
			No authentication
			Integrity (Detects tampering of data)

CIA:
	Confidentiality:
		Prevent unauthorized access
		Done by:
			SSL/TLS
			Role based access
			MFA
	Integrity:
		Ensure data is not altered
		Done by:
			Checksums
			Hashing
			Constraints like foreign key
	Availabillity:
		Ensure data is available when needed
		Done by:
			Implementing disaster recovery, backups
			firewalls, rate limit apis, detect and neutralize DDoS

MAC:
	is a short piece of information that ensures integrity and authenticity.
	Ensures message is not tampered and was sent by authenticated person who knows the shared secret key.
	examples: JWT

DHCP:
	is a network management protocol used to assign ip address to devices connecting to the network.
	Solves:
		Assigns IP address
		Provides subnet mask
		Shares default gateway
		Supplies DNS server info

FTP:
	is a protocol used to transfer files between two devices connected over a network.
	Two connection:
		Control connection - handles FTP commands (GET, PUT) - port 21
		Data connection - transfers files
			Active Data Connection:
				server initiates session
			Passive Data Connection:
				client initiates session
	Data sent as plain text
	Uses TCP/IP so, reliable

FTPS:
	FTP + SSL/TLS
	Adds encryption to FTP
		Explicit FTPS - Client requests Encryption using Auth TLS command
		Implicit FTPS - Encryption starts automatically | on different port(usually port 900)
SFTP:
	Not related to FTP or FTPS, despite the name.
	It is completly different protocol built as part of ssh.
	Operates over port 22, uses single connection for commands and data transfer

ICMP: Internet Control Message Protocol
	used only to report succes or failure of communication between network devices.

Ping:
	used to test network connectivity
	More delay means, problem with network or server. If server, sign of DDoS
	ping google.com
traceroute:
	used to see the path / hops made by packet reach specific server.
	traceroute google.com


whois <ipaddress>
geoiplookup <ipaddress>
ip a 
ip route (shows routers address)
curl ipconfig.me  (shows routers pubic ip)

Stolen JWT:
	What is someone steals the JWT and performs abnormal activities: here JWT is used to track any user?
		From the request made to our server, we can see the client information such as browser, OS, geolocation,time. If we notice sudden changes on these informations what should SOC have to do?
			-> Invalidate or blacklist suspected JWT
			-> Re-authenticate user by force logout or token refresh
			-> Investigate how the token has stolen
		
		If the attacker uses same client applications and routes his traffic through VPNs at actual users geolocation, It'd difficult to trace. Here what should we do?
			-> Use tools like FingerprintJS to deep analyze subtle differences such as font size, screen resolution, webGL support, etc.
			-> 
		
		Talking about mitigating this issue: how can we detect and resolve this issue?

we can flag this user and keep an eye on his activities.
check through his past activities, detect any abnormality in his recent sessions or privilage escalation activities, we can flag this user .......... . 
If we encounter such abnormality, we can ask them to relogin, force a password reset, ask them to enable MFA, send a security alert to actual email.

how RSA, AES works?