import sys
from scapy.all import *


# retrieves a domain's dns server
def getDNSServer(domain):
    # create a first inquiry packet to find the relevant dns server
    pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname=domain, qtype="SOA"))
    response = sr1(pkt)
    if not(response and response.an):
        print("No response received. try again later")
        return
    # print the name of the dns server and return it
    dns_server = response.an.mname.decode()
    print(f"DNS server name: {dns_server}")
    return dns_server


# retrieves all subdomains of a passed domain by scanning common keywords
def dnsmap(domain):
    # first we'll find the dns server which holds our domain
    dns_server = getDNSServer(domain)
    # if for some reason we couldn't find the domain
    if dns_server is None:
        return
    with open("options.txt") as f:
        for term in f:
            # get rid of any "\n" and similar notes
            term = term.strip()
            # create our new query to try
            query_name = f"{term}.{domain}"
            # create and send a packet to see if the address we are looking for is in the dns server. rd represents our
            # recursion depth which doesn't need to be too high in this case
            pkt = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name, qtype="A"))
            # timeout represents how long we want to wait for each request. this can be made adjustable in
            # future versions. verbose simplifies the response and suppresses extra output we won't need
            response = sr1(pkt, timeout=2, verbose=0)
            # if we get a valid response which includes a valid answer
            if response and response.an:
                # print the name of the subdomain
                print(query_name)
                # loop over all answers in case there are multiple
                for i in range(response.ancount):
                    answer = response.an[i]
                    # only print the IP addresses
                    if answer.type == 1:
                        print(response.an[i].rdata)
                # new line in between subdomains
                print()


def main():
    # make sure a parameter was passed
    if len(sys.argv) < 2:
        print("No param passed on call")
        sys.exit()
    dnsmap(sys.argv[1])


if __name__ == "__main__":
    main()
