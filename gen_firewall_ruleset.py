import csv
import os
import random
import re
import string
import json
import numpy
import glob
from collections import defaultdict

def fetch_bus_network(fr_network_model):
    alphabet = list(string.ascii_uppercase)
    read_b_net_conf = open("bus/network_bus.diag", "r")
    read = read_b_net_conf.readlines()
    count = 0
    site_names = []
    gateways = defaultdict(list)
    net_address = defaultdict(list)
    hosts = defaultdict(list)
    for line in read: # Read the network configuration file for the bus topology and extract details based on the configuration identifier
        if "network site%s" % alphabet[count] in line:
            site_names.append(re.findall('site%s' % alphabet[count], line)[0])
            count+=1
        if "    gw" in line:
            gateways[alphabet[count-1]].append(line[4:-2])
        if "    address" in line:
            net_address[alphabet[count-1]].append(line[4:-2])
        if "    %s" % alphabet[count-1] in line:
            hosts[alphabet[count-1]].append(line[4:-1])
    if fr_network_model == "b":
        gen_gw_firewall(site_names, gateways, net_address, hosts, mode="b")
    if fr_network_model == "x":
        return site_names, gateways, net_address, hosts

def fetch_star_network():
    alphabet = list(string.ascii_uppercase)
    site_names = []
    net_address_temp = []
    net_address = defaultdict(list)
    hosts = defaultdict(list)
    gateways = defaultdict(list)
    count = 0
    read_s_net_conf = open("star/network_star.txt", "r")
    read = read_s_net_conf.readlines()
    for line in read: # Read the network configuration file for the star topology and extract details based on the fixed format of the file
        if "/" in line:
            net_address_temp.append(line[:-1])
        if alphabet[count] in line:
            if line[1].isdigit():
                char_store_host = []
                char_store_r = []
                flag = 0
                for char in line:
                    if char == "<":
                        flag = 1
                    if flag == 0:
                        char_store_host.append(char)
                    if flag == 1:
                        char_store_r.append(char)
                hosts[alphabet[count]].append(''.join(char_store_host[:-1]))
        if line[0] == "R" and line[1] == "(":
            count+=1
            flag_r = 0
            char_store_gw_1 = []
            char_store_gw_2 = []
            for char in line:
                if char == "<":
                    flag_r = 1
                if flag_r == 0:
                    char_store_gw_1.append(char)
                if flag_r == 1:
                    char_store_gw_2.append(char)
            gateways[alphabet[count]].append(''.join(char_store_gw_1[:-1]))
            gateways[alphabet[count]].append(''.join(char_store_gw_2[8:-1]))
    net_address_temp.pop()
    hosts["A"].pop(0)
    for x in net_address_temp:
        site_names.append("site"+x[-1])
        net_address[x[-1]].append(x[:-4])
    gen_gw_firewall(site_names, gateways, net_address, hosts, mode="s")

def gen_gw_firewall(site_names, gateways, net_address, hosts, mode):
    num_of_gateways = None
    fetch_ports = []
    fw_rs = None
    host_to_gw_match = []
    alphabet = list(string.ascii_uppercase)
    if mode == "b":
        num_of_gateways = len(site_names) - 1
        csv_read = csv.reader(open('bus/default_routing_b.csv','r'))
        count = 0
        for row in csv_read: # Read the default routing of the bus model and extract one host from every subnet to determine which gateways are present
            if row:
                if row[0] == alphabet[count]+"1":
                    host_to_gw_match.append(row)
                    count+=1
    firewall_mode = 0
    print("num of gateways: " + str(num_of_gateways))
    print(site_names)
    print("Net address " + str(dict(net_address)))
    print("Hosts " + str(dict(hosts)))
    print("Gateways " + str(dict(gateways)))
    for p in hosts["A"]: # Extract services from the trailing end of the each host in the server farm (A)
        fetch_ports.append(p.rsplit(' ', 1)[1])
    print(fetch_ports)
    print(len(fetch_ports))
    port_allocation = numpy.array_split(numpy.array(fetch_ports), len(site_names)-1) # Distribute services used in the server farm evenly between the sites
    host_to_gw_match.reverse()
    fw_rules_prior = []
    count_ref = 0
    fw_rules = []
    skip_gw = 0
    fw_rules_merge = []
    for enum, x in enumerate(host_to_gw_match): # Iterate through the gateways in the network
        print(port_allocation)
        if enum == 0 or enum == 1:  # Create ruleset for gateways at base of network serving two subnets
            for y in hosts[str(x[0][0])]: # for each host in the subnet
                fw_single_rule_in = {
                    "Ref #": count_ref,
                    "Chain": "FORWARD",
                    "Source": hosts["A"][enum].replace('"',"'"), #Take a host from the server farm
                    "Destination": y[:-1].replace('"',"'"), # Take a host from the iterated subnet
                    "Port": hosts["A"][enum].replace('"',"'").rsplit(' ', 1)[1], # Take the port from the trailing end of the source
                    "Policy": "ACCEPT",
                }
                fw_rules.append(fw_single_rule_in)
                fw_rules_prior.append(fw_single_rule_in)
                count_ref += 1
            for y in hosts[str(x[0][0])]: # Duplicate of above with swapped source and destination for bi-directional traffic
                fw_single_rule_out = {
                    "Ref #": count_ref,
                    "Chain": "FORWARD",
                    "Source": y[:-1].replace('"',"'"),
                    "Destination": hosts["A"][enum].replace('"',"'"),
                    "Port": hosts["A"][enum].replace('"',"'").rsplit(' ', 1)[1],
                    "Policy": "ACCEPT",
                }
                fw_rules.append(fw_single_rule_out) # Store for use in writing to the ruleset
                fw_rules_prior.append(fw_single_rule_out) # Store for use in later gateways
                count_ref += 1
            if mode == "b":
                fw_rs = open("bus/fw_b/fw_rs_gw%s.json" % host_to_gw_match[0][2][2], "w")
            serialize_rules = json.dumps(fw_rules, indent=4) # Serialise rules generated into json
            fw_rs.write(serialize_rules) # write to file
            fw_rs.close()
        if enum == len(host_to_gw_match)-1: # server farm
            fw_rules = []
            count_ref = 0
            site_sel = " - site%s" % alphabet[len(site_names)-1] + "/" + alphabet[len(site_names)-2] # Determine the sites of which a gateway are efaulted to
            if mode == "b":
                fw_rs = open("bus/fw_b/fw_rs_gw%s.json" % x[2][2], "w")
            print(port_allocation)
            gateways_reverse = list(gateways.values())
            gateways_reverse = [item for sublist in gateways_reverse for item in sublist]
            gateways_reverse.reverse()
            print(gateways_reverse)
            if firewall_mode == 0:
                for track_sn, y in enumerate(port_allocation):
                    fw_single_rule_in = {
                        "Ref #": count_ref,
                        "Chain": "FORWARD",
                        "Source": gateways_reverse[1+skip_gw].replace('"', "'") + site_sel, # Iteratively selects each gateway in the network and its subsequent sites
                        "Destination": hosts["A"][track_sn].replace('"',"'"), # Iteratively selects a server in the server farm which the hosts in the gateway sites will use
                        "Port": hosts["A"][track_sn].replace('"',"'").rsplit(' ', 1)[1], # Take the port from the trailing end of the destination
                        "Policy": "ACCEPT",
                    }
                    fw_rules.append(fw_single_rule_in)
                    count_ref += 1
                    if track_sn != 0:
                        skip_gw += 2
                        site_sel = " - site%s" % alphabet[len(site_names) - 2 - track_sn]
                skip_gw = 0
                site_sel = " - site%s" % alphabet[len(site_names) - 1] + "/" + alphabet[len(site_names) - 2]
                for track_sn, y in enumerate(port_allocation): # Duplicate of above with swapped source and destination for bi-directional traffic
                    fw_single_rule_out = {
                        "Ref #": count_ref,
                        "Chain": "FORWARD",
                        "Source": hosts["A"][track_sn].replace('"',"'"), #y[:2],
                        "Destination": gateways_reverse[1+skip_gw].replace('"', "'") + site_sel, # hosts["A"][enum].replace('"',"'"), #"siteA",
                        "Port": hosts["A"][track_sn].replace('"',"'").rsplit(' ', 1)[1],
                        "Policy": "ACCEPT",
                    }
                    fw_rules.append(fw_single_rule_out)
                    count_ref += 1
                    if track_sn != 0:
                        skip_gw += 2
                        site_sel = " - site%s" % alphabet[len(site_names) - 2 - track_sn]
                serialize_rules = json.dumps(fw_rules, indent=4)
                fw_rs.write(serialize_rules)
                fw_rs.close()
        if enum >= 2 and enum != len(host_to_gw_match)-1: # Intermediary firewalls - follow an identical process to the base of the network with the addition of appending rules generated in previous rulesets
            print(x)
            fw_rules = fw_rules_merge[:]
            print(fw_rules)
            if mode == "b":
                fw_rs = open("bus/fw_b/fw_rs_gw%s.json" % x[2][2], "w+")
            print(port_allocation)
            if firewall_mode == 0:
                for y in hosts[str(x[0][0])]:
                    fw_single_rule_in = {
                        "Ref #": count_ref,
                        "Chain": "FORWARD",
                        "Source": hosts["A"][enum].replace('"',"'"),
                        "Destination": y[:-1].replace('"',"'"),
                        "Port": hosts["A"][enum].replace('"',"'").rsplit(' ', 1)[1],
                        "Policy": "ACCEPT",
                    }
                    fw_rules.append(fw_single_rule_in)
                    count_ref += 1
                for y in  hosts[str(x[0][0])]:
                    fw_single_rule_out = {
                        "Ref #": count_ref,
                        "Chain": "FORWARD",
                        "Source": y[:-1].replace('"',"'"),
                        "Destination": hosts["A"][enum].replace('"',"'"),
                        "Port": hosts["A"][enum].replace('"',"'").rsplit(' ', 1)[1],
                        "Policy": "ACCEPT",
                    }
                    fw_rules.append(fw_single_rule_out)
                    count_ref += 1
                if enum != len(host_to_gw_match)-2:
                    fw_rules_merge = fw_rules_prior + fw_rules # Append rules of prior gateways if not directly attached
                else:
                    fw_rules_merge = fw_rules
                serialize_rules = json.dumps(fw_rules_merge, indent=4)
                fw_rs.write(serialize_rules)
                fw_rs.close()
    insert_misconfiguration(site_names) # Call misconfiguration process
    exit()

def insert_misconfiguration(site_names):
    firewall_rulesets = []
    print("number of firewalls " + str(len(site_names)-1))
    for file in glob.glob("bus/fw_b/*.json"): # umutto (2017) iterate over multiple files [Snippet]. https://stackoverflow.com/a/42499584 [Accessed 14/05/21]
        firewall_rulesets.append(file) # Create a list of every json file in the bus firewall folder
    firewall_rulesets.pop(0) # remove server farm ruleset as it wont be targeted for misconfiguration
    chosen_firewall_misconfig = random.choice(firewall_rulesets)
    print(chosen_firewall_misconfig)
    with open(chosen_firewall_misconfig, "r") as file:
        misconfig_file = json.load(file)
    pick_insertion_point = random.randint(1,len(misconfig_file))
    before_or_after_insertion_point = random.choice([-1,1])
    with open(chosen_firewall_misconfig, "w") as file: # write a permissive any any rule using the port of the rule at insertion point
        fw_any_any_rule = {
            "Ref #": "misconfig_any",
            "Chain": "FORWARD",
            "Source": "'any'",
            "Destination": "'any'",
            "Port": misconfig_file[pick_insertion_point]["Port"],
            "Policy": "ACCEPT",
        }
        misconfig_file.insert(pick_insertion_point+before_or_after_insertion_point,fw_any_any_rule) # Insert rule into firewall ruleset
        print(misconfig_file[pick_insertion_point+before_or_after_insertion_point])
        serialize_rules = json.dumps(misconfig_file, indent=4)
        file.write(serialize_rules) # Write to json file
    exit()

def main():
    while True:
        fr_network_model =  "b" # Hard coded to only select bus as no firewall generation is avaiable with star - input(str("Choose a network model previously generated in old_gen_network_single_homed.py to generate firewall rulesets:\nBus topology (b), Star Topology (s): "))
        if fr_network_model.casefold() == "b".casefold():
            filelist = [f for f in os.listdir("bus/fw_b") if f.endswith(".json")] # miku (2010) Deleting all files in a directory [Snippet]. https://stackoverflow.com/a/1995397 [Accessed 14/05/21]
            for f in filelist:
                os.remove(os.path.join("bus/fw_b", f)) # Remove every json file in the bus firewall folder
            fetch_bus_network(fr_network_model)
        elif fr_network_model.casefold() == "s".casefold():
            fetch_star_network()
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
