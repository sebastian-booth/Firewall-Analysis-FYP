import gen_firewall_ruleset as gfs
import string
import itertools
import csv
import json
import re

def translate_fw():
    '''
    This function demonstrates a conceptual method of third party firewall formats could be translated into a custom
    abstraction. Due to the lack of testable sample data and the complexity of predetermining the format of every third
    party firewall this function remains a theoretical example
    '''
    flag = 1
    chain = []
    src_add = []
    dest_add = []
    port = []
    policy = []
    count = 0
    fw_file = None
    while flag == 1: # In a loop request an input for the path of a firewall ruleset until a valid path is entered
        ruleset_input = input(str("Enter the full absolute path of the chosen firewall ruleset (in .txt or .json format): "))
        try:
            fw_file = open(ruleset_input, "r")
            flag = 0
        except FileNotFoundError:
            print("File Not Found")
    lines = fw_file.readlines()
    translated_fw = open("bus/translated_fw.json" , "w")
    for x in lines: # Iterate through the lines of loaded ruleset and determine certain firewall configurations using keywords if said keywords were met, then store the entire line in a list
        if "chain" in x.lower() or "output" in x.lower() or "input" in x.lower() or "forward" in x.lower() and len(chain) != 1:
            print(x) # Add to chain list
            chain.append(x)
        if "source" in x.lower() or "src" in x.lower() and len(src_add) != 1:
            print(x) # Add to src_add list
            src_add.append(x)
        if "destination" in x.lower() or "dest" in x.lower() or "dst" in x.lower() and len(dest_add) != 1:
            print(x) # Add to dest_add list
            dest_add.append(x)
        if "port" in x.lower() or "service" in x.lower() and len(port) != 1:
            print(x) # Add to port list
            port.append(x)
        if "policy" in x.lower() and len(policy) != 1:
            print(x) # Add to policy list
            policy.append(x)
        if len(chain) == 1 and len(src_add) == 1 and len(dest_add) == 1 and len(port) == 1 and len(policy) == 1:
            fw_single_rule = { # If required parameter is filled then form into rule and write to a json file
                "Ref #": count,
                "Chain": chain[0],
                "Source": src_add[0],
                "Destination": dest_add[0],
                "Port": port[0],
                "Policy": policy[0]
            }
            serialize_rules = json.dumps(fw_single_rule, indent=4)
            translated_fw.write(serialize_rules)
            count+=1
            chain = [] # Reset the network configuration parameters
            src_add = []
            dest_add = []
            port = []
            policy = []
    exit()

def analyse_pathways():
    network_info = gfs.fetch_bus_network("x") # Fetch the network configuration information using the previsouly defined function
    any_any_route = []
    comms_scenario = []
    rule_search = []
    outgoing_verify = []
    incoming_verify = []
    def_gw = None
    hosts = network_info[3]
    services = []
    for y in hosts["A"]: # Extract services from the trailing end of the each host in the server farm (A)
        services.append(y.split()[-1])
    flat_hosts = sorted({x for v in hosts.values() for x in v}) # nneonneo (2012 Flatten a dict of lists into unique values [Snippet]. https://stackoverflow.com/a/13016200 [Accessed 14/05/21]
    print(flat_hosts)
    perm = itertools.permutations(list(flat_hosts),2) # Take the list of all hosts in the network and create permutations between then
    for i in perm:
        i = list(i)
        for m in services: # Rerun these permutations through another process to further permutate against every port used in the network
            i.append(m)
            comms_scenario.append(list(i))
            i.pop()
    print(hosts["A"])
    comms_scenario_iter = comms_scenario[:]
    for s in comms_scenario_iter:
        if s[0][0] == "A" and s[1][0] == "A":
            comms_scenario.remove(s) # Remove any communication scenario between two server farm hosts - Valid implementation of these pathways could not be implemented
    file_dr = open("bus/default_routing_b.csv", "r")
    read_dr = list(csv.reader(file_dr))
    file_gw = open("bus/gw_routing_b.csv", "r")
    read_gw = list(csv.reader(file_gw))
    for x in comms_scenario: # For each communication scenario
        traversal = []
        flag = 1
        onlink = False
        for row_dr in read_dr: # Determine the default gateway of the source
            if str(x[0][:2]) == row_dr[0]:
                def_gw = row_dr[2]
                #print(row_dr)
        for row_gw in read_gw: # Determine the series of intermediary gateways the packet must traverse
            if flag == 1 and def_gw[:3] == row_gw[3][:3]:
                traversal.append(row_gw[0])
                flag = 0
        while onlink == False:
            for row_gw in read_gw: # Cease the traversal of gateways once an on-link route is shown
                if traversal[-1] == "On-":
                    onlink = True
                if row_gw[0] == traversal[-1]:
                    if row_gw[1][4] == str(x[1][0]):
                        #print(row_gw)
                        traversal.append(row_gw[2][:3])
        if traversal[-1] == "On-":
            traversal.pop()

        print(str(x[0]) + " travels through gateways and firewalls in order: " + str(traversal) + " to reach " + str(x[1]) + " via port " + str(x[2]))
        print("\n")

        # enumerate the initial message in the communication
        passthrough_gw = []
        for enum, gw in enumerate(traversal):
            firewall_load = open("bus/fw_b/fw_rs_%s.json" % gw) # Read each firewall ruleset
            firewall = json.load(firewall_load)
            if gw != "gw0": # If the firewall does not belong to gw0 (the server farm)
                source = re.findall(r'"([^"]*)"', str(x[0]))[0].rstrip() # Take the ip from the source host in the communication
                destination = re.findall(r'"([^"]*)"', str(x[1]))[0].rstrip() # Take the ip from the destination host in the communication
                port = str(x[2]).rstrip() # Take the port from the communication scenario
                for rule in firewall: # Iterate the firewall
                    if (re.findall(r"'([^']*)'", rule["Source"])[0]).rstrip() == source and (re.findall(r"'([^']*)'", rule["Destination"])[0]).rstrip() == destination and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule) # If the iterated firewall rule values are equivalent to that of the communcation scenario, store the communication scenario as valid
                        passthrough_gw.append(gw)
                    if rule["Source"] == "'any'" and rule["Destination"] == "'any'" and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule) # If the iterated firewall rule values are equivalent to any-any and the port in the scenario, store the communication scenario as an any any route
                        any_any_route.append("ANY ANY TRAFFIC MESSAGE " + str(x[0]) + " travels through firewalls: " + str(traversal) + " to reach " + str(x[1]) + " via port " + str(x[2]))
                        rule_search.append(str(rule).replace("\\", "")) # store the any any rule
                    else:
                        pass
            else:
                source = traversal[0]
                destination = re.findall(r'"([^"]*)"', str(x[1]))[0].rstrip()
                port = str(x[2]).rstrip()
                for rule in firewall:
                    if source in rule["Source"][:3].rstrip() and (re.findall(r"'([^']*)'", rule["Destination"])[0]).rstrip() == destination and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule) # Verify check the pathways which are allowed by the server farm firewall by checking against the individual servers and subnet gateways
                        passthrough_gw.append(gw)
                    else:
                        pass
        print(passthrough_gw)
        print(traversal)
        if passthrough_gw == traversal: # If all firewalls were satisfied in the traversal store the scenario
            outgoing_verify.append("VERIFIED TRAFFIC MESSAGE " + str(x[0]) + " travels through firewalls: " + str(traversal) + " to reach " + str(x[1]) + " via port " + str(x[2]))

        # Conduct the same process as a above but reversing the traversal steps and swapping the destination and source addreses
        # enumerate fw backward
        reverse_traveral = traversal[::-1]
        passthrough_gw = []
        for enum, gw in enumerate(reverse_traveral):
            firewall_load = open("bus/fw_b/fw_rs_%s.json" % gw)
            firewall = json.load(firewall_load)
            if gw != "gw0":
                destination = re.findall(r'"([^"]*)"', str(x[0]))[0].rstrip()
                source = re.findall(r'"([^"]*)"', str(x[1]))[0].rstrip()
                port = str(x[2]).rstrip()
                for rule in firewall:
                    if (re.findall(r"'([^']*)'", rule["Source"])[0]).rstrip() == source and (re.findall(r"'([^']*)'", rule["Destination"])[0]).rstrip() == destination and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule)
                        passthrough_gw.append(gw)
                    if rule["Source"] == "'any'" and rule["Destination"] == "'any'" and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule)
                        any_any_route.append("ANY ANY TRAFFIC RESPONSE " + str(x[0]) + " travels through firewalls: " + str(traversal) + " to reach " + str(x[1]) + " via port " + str(x[2]))
                        rule_search.append(str(rule).replace("\\", ""))
                    else:
                        pass
            else:
                source = reverse_traveral[-1]
                destination = re.findall(r'"([^"]*)"', str(x[1]))[0].rstrip()
                port = str(x[2]).rstrip()
                for rule in firewall:
                    if source in rule["Source"][:3].rstrip() and (re.findall(r"'([^']*)'", rule["Destination"])[0]).rstrip() == destination and port in rule["Port"] and rule["Policy"] == "ACCEPT":
                        print(rule)
                        passthrough_gw.append(gw)
                    else:
                        pass
        print(passthrough_gw)
        print(reverse_traveral)
        if passthrough_gw == reverse_traveral:
            incoming_verify.append("VERIFIED TRAFFIC RESPONSE " + str(x[1]) + " travels through firewalls: " + str(reverse_traveral) + " to reach " + str(x[0]) + " via port " + str(x[2]))
    for t in outgoing_verify: # Print the discovered pathways
        print(t)
    print("\n")
    for n in incoming_verify:
        print(n)
    print("\n\n")
    for i in any_any_route:
        print(i)
    print("Number of any any pathways: " + str(len(any_any_route)))
    if len(any_any_route) > 100: # If the number of any-any routes is greater than 100
        print("Possible hidden pathway detected by one of the following rules:")
        for w in list(set(rule_search)): # Print all rules identified as any any
            print(w)
    exit()

def main():
    while True:
        fr_network_model = input(str("Translate a firewall ruleset into custom abstraction (t) or analyse communication pathways using the custom abstraction (a): "))
        if fr_network_model.casefold() == "t".casefold():
            translate_fw()
        elif fr_network_model.casefold() == "a".casefold():
            analyse_pathways()
        else:
            print("Invalid option")

main()