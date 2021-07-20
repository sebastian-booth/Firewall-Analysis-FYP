This readme will provide a step by step walkthrough describing how the code is used and the its results are
interpreted:

Commands to run in a terminal are defined by the contents between two square brackets.

Step 1: Ensure Python 3.7.0 and pip3 is installed and can be initialised by running [python] and [pip3] in a terminal,
        no other version of python is guaranteed to work with this code. Depending on how the instance of python was
        installed the correct command to verify the installation of python 3 would be to run [python3]

Step 2: Install the required python libraries by opening a terminal in the same directory as this readme and run
        [pip3 install -r requirements.txt]

* Note the following tools must be run in the order given below and throughout their execution runtime and debugging information
    will be displayed, this can be ignored unless otherwise stated.

Step 3: Run the tool gen_network_multi_homed.py in a terminal using [python gen_network_multi_homed.py]. Note this tool
        can take some time to complete

        Step 3a: Input "b" when prompted to generate a bus topology model which is the primary model used throughout the
                 tools or input "s" to generate a star topology model. Once completed displaying
                 "Process finished with exit code 0" the output of the tool can be viewed in either the bus or star
                 folder depending on what was chosen. Outputs for both include: a network diagram image, a configuration
                 file for the network and two csv files, one for the default routing used by each host and another for
                 the linked gateway routes. These are named as appropriate.

Step 4: Run the tool gen_firewall_ruleset.py in a terminal using [python gen_firewall_ruleset.py]. No input is required
        and the output of this function will be a number of firewall rulesets stored as json files in the folder
        code/bus/fw_b. Note at least one generation of a bus topology model in step 3 must have been completed 
	(in circumstances where only a star topology was chosen)

Step 5: Run the tool analyse_firewalls.py in a terminal using [python analyse_firewalls.py]. Note this tool can take
        some time to complete.

        Step 5a: Input "a" to begin analysing the firewall rulesets created for the bus network environment. Once
                 completed showing "Process finished with exit code 0" several pieces of information will be displayed
                 in the terminal this is broken down into four sections:
                    1. VERIFIED TRAFFIC MESSAGE - This will show the successful communication scenarios of a message
                                                  being sent between two hosts over a specific port
                    2. VERIFIED TRAFFIC RESPONSE - This will show the successful communication scenarios of a response
                                                  to the message sent prior between two hosts over a specific port
                    3. ANY ANY TRAFFIC MESSAGE/RESPONSE - This will show all of the communication scenarios that were
                                                           satisfied by a pathway containing permissive any source,
                                                           any destination parameters
                    4. Summary of findings - This will display the number of any any pathways found, along with all
                                            permissive any any rules extracted from the rulesets which are likely
                                            exploitable hidden opportunities for lateral movement
                 Input "t" when prompted when starting the tool to test the experimental firewall translator,
                 this will lead into another input which will request the full path of the chosen firewall to be
                 translated. If this file is valid it will output a file: code/bus/translated_fw.json containing
                 the abstracted ruleset