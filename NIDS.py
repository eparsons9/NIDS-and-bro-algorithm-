import csv
import matplotlib.pyplot as plt
from collections import defaultdict
from TestNIDS import *


def parse_netflow():
    """Use Python's built-in csv library to parse netflow.csv and return a list
       of dictionaries. The csv library documentation is here:
       https://docs.python.org/3/library/csv.html"""
    with open('netflow.csv', 'r') as netflow_file:
        netflow_reader = csv.DictReader(netflow_file)
        netflow_data = list(netflow_reader)
        return netflow_data


def is_internal_IP(ip):
    """Return True if the argument IP address is within campus network"""
    s = ip.split('.')
    if s[0] == "128" and s[1] == "112":
        return True
    return False


def plot_bro(num_blocked_hosts):
    """Plot the list of the number of Bro blocked hosts indexed by T"""
    fig = plt.figure(figsize=(16,8))
    plt.plot(range(len(num_blocked_hosts)), num_blocked_hosts, linewidth=3)
    plt.xlabel("Threshold", fontsize=16)
    plt.ylabel("Number of Blocked Hosts", fontsize=16)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.title("Sensitivity of Bro Detection Algorithm", fontsize=16)
    plt.grid()
    plt.savefig("sensitivity_curve.png")


def detect_syn_scan(netflow_data):
    """TODO: Complete this function as described in readme.txt"""
    syn_only = 0
    TCP = 0
    for flow in netflow_data:
        flag = flow["Flags"]
        protocol = flow["Protocol"]
        if protocol == "TCP":
            if "S" in flag and "A" not in flag:
                syn_only+= 1
            TCP += 1


    percent_synonly = (syn_only / TCP) * 100

    # Do not change this print statement
    print("\nPercent SYN-only flows: {} -> {}\n".format(
        percent_synonly, test_percent_synonly(percent_synonly)))


def detect_portscan(netflow_data):
    """TODO: Complete this function as described in readme.txt"""

    # Your code here
    synonly_knownbad = []           # default value
    synonly_NOTknownbad = []        # default value
    other_knownbad = []             # default value      
    other_NOTknownbad = []          # default value

    percent_knownbad = 0            # default value
    percent_synonly_knownbad = 0    # default value
    percent_synonly_NOTknownbad = 0 # default value

    TCP=0

    for flow in netflow_data:
        port = flow["Dst port"]
        protocol = flow["Protocol"]
        flag = flow["Flags"]
        if protocol == "TCP":
            if "S" in flag and "A" not in flag:
                if port in ["135", "139", "445", "1433"]:
                    synonly_knownbad.append(flow)
                else:
                    synonly_NOTknownbad.append(flow)
            else:
                if port in ["135", "139", "445", "1433"]:
                    other_knownbad.append(flow)
                else:
                    other_NOTknownbad.append(flow)
            TCP += 1

    len_syn_known=len(synonly_knownbad)
    len_other_known=len(other_knownbad)
    len_syn_not=len(synonly_NOTknownbad)

    percent_knownbad = (len_syn_known+ len_other_known) / TCP * 100
    percent_synonly_knownbad = (len_syn_known / (len_syn_known + len_other_known)) * 100
    percent_synonly_NOTknownbad = (len_syn_not / (len_syn_not + len(other_NOTknownbad))) * 100
  


    # Do not change these statments
    print("Precent of TCP flows to known bad ports: {} -> {}".format(
        percent_knownbad, test_percent_knownbad(percent_knownbad)))
    print("Percent of SYN-only TCP flows to known bad ports: {} -> {}".format(
        percent_synonly_knownbad, test_percent_synonly_knownbad(percent_synonly_knownbad)))
    print("Percent of SYN-only TCP flows to other ports: {} -> {}\n".format(
        percent_synonly_NOTknownbad, test_percent_synonly_NOTknownbad(percent_synonly_NOTknownbad)))
    return synonly_knownbad, synonly_NOTknownbad, other_knownbad, other_NOTknownbad


def detect_malicious_hosts(netflow_data, synonly_knownbad, synonly_NOTknownbad, 
                           other_knownbad, other_NOTknownbad):
    """TODO: Complete this function as described in readme.txt"""

    # Your code here
    num_malicious_hosts = 0    # default value
    num_benign_hosts = 0       # default value
    num_questionable_hosts = 0 # default value

    malicious_hosts = set()
    benign_hosts = set()
    questionable_hosts = set()

    
    for address in synonly_knownbad:
        ip = address.get("Src IP addr")
        if not is_internal_IP(ip) and ip not in malicious_hosts:
                malicious_hosts.add(ip)
    
    for address in synonly_NOTknownbad:
        ip = address.get("Src IP addr")
        if not is_internal_IP(ip) and ip not in malicious_hosts:
            malicious_hosts.add(ip)

    for address in other_knownbad:
        ip = address.get("Src IP addr")
        if not is_internal_IP(ip) and ip not in malicious_hosts:
            malicious_hosts.add(ip)

    for address in other_NOTknownbad:
        ip = address.get("Src IP addr")
        if not is_internal_IP(ip):
            benign_hosts.add(ip)

    benign_copy = benign_hosts.copy()

    for ip in benign_copy:
        if ip in malicious_hosts:
            questionable_hosts.add(ip)
            malicious_hosts.remove(ip)
            benign_hosts.remove(ip)
            
            
    num_malicious_hosts = len(malicious_hosts)
    num_benign_hosts = len(benign_hosts)
    num_questionable_hosts = len(questionable_hosts)

    #for ip in malicious_hosts:
   #     print(ip)
 
    # Do not change these print statments
    print("Number of malicious hosts: {} -> {}".format(
        num_malicious_hosts, test_num_malicious_hosts(num_malicious_hosts)))
    print("Number of benign hosts: {} -> {}".format(
        num_benign_hosts, test_num_benign_hosts(num_benign_hosts)))
    print("Number of questionable hosts: {} -> {}\n".format(
        num_questionable_hosts, test_num_questionable_hosts(num_questionable_hosts)))
failed_connections_one= set()
failed_connections_two = set()

srcCheck = set()

class Bro:
    """TODO: complete this class to implement the Bro algorithm"""
    
    def __init__(self, threshold):
        # self.T is the threshold number of unique destination addresses from
        #     successful and/or failed connection attempts (depending on port)
        #     before a host is marked as malicious
        self.T = threshold
        
        
        # self.good_services is the list of port numbers to which successful connections 
        #     (SYN and ACK) should not be counted against the sender
        self.good_services = [80, 22, 23, 25, 113, 20, 70]

        # You may add additional class fields and/or helper methods here
    

    

    def run(self, netflow_data):
        """TODO: Run the Bro algorithm on netflow_data, returning a 
                 set of blocked hosts. You may add additional helper methods 
                 or fields to the Bro class"""
        
        
        #for flow in netflow_data: # loop simulates an "online" algorithm 
            # Your code here
        blocked_hosts = set()
        count = {}
 
        for flow in netflow_data:
            srcIP = flow["Src IP addr"]
            internal_src=is_internal_IP(srcIP)
            if not internal_src:
                protocol = flow["Protocol"]
                flags = flow["Flags"]
                port = flow["Dst port"]
                dstIP = flow["Dst IP addr"]
                internal_dst= is_internal_IP(dstIP)
                if internal_dst and protocol=="TCP":
                    self.check_flags(count, srcIP, flags, port, dstIP)

                    
        for key in count:
            x= count.get(key)
            if len(x) > self.T:
                blocked_hosts.add(key) 
           
        
   
        
        # Do not change this return statement
        return blocked_hosts

    
        
    def check_flags(self, count, srcIP, flags, port, dstIP):
        if ("S" in flags and "A" not in flags):
            if port in self.good_services:
                key= count.get({srcIP:[dstIP]})
                if key==-1:
                    count.update({srcIP:[dstIP]})
                else:
                    val=count.get(srcIP)
                    if dstIP not in val:
                        val.append(dstIP)
                        count[srcIP]=val
        if ("S" not in flags and "A" in flags) or ("A" not in flags and "S" in flags):
            if port not in self.good_services:
                key= count.get(srcIP, -1)
                if key==-1:
                    count.update({srcIP:[dstIP]})
                else:
                    val=count.get(srcIP)
                    if dstIP not in val:
                        val.append(dstIP)
                        count[srcIP]=val

   
        
        
        
   
    
def main():
    """Run all functions"""
    netflow_data = parse_netflow()
    detect_syn_scan(netflow_data)
    portscan_flows = detect_portscan(netflow_data)
    detect_malicious_hosts(netflow_data, *portscan_flows)
    num_blocked_hosts = [len(Bro(T).run(netflow_data)) for T in range(1, 121)]
    plot_bro(num_blocked_hosts)
    print("Bro sensitivity curve plotted")


if __name__=="__main__":
    main()
