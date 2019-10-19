import csv


class Firewall:

    # Ideally the csv would have a row with the names of each of the columns
    # this would make it so that we could easily identify the index of all
    # categorical values in the rules
    # This is important because then we can write a function to generate
    # the keys that are used below
    
    def __init__(self, path):
        self.rules = {}
        self.__process_file(path)
    
    def __process_file(self, path):
        
        with open(path) as csv_file:
            
            csv_reader = csv.reader(csv_file, delimiter=',')
            
            for row in csv_reader:
                
                # Categorical values can all go in this string
                # This will serve as key to narrow rules down
                # This makes it harder to analyze which rules exist from this dictionary
                # However this approach saves a great deal of time and makes
                # the code more concise.
                # Ideally that array which goes in the function can be generated
                # automatically using information about the columns
                key = self.__generate_key([row[0], row[1]])
                
                if key not in self.rules:
                    self.rules[key] = []
                
                # Each counting value is added via their respective
                # "processing" function which converts the string into a list
                counting_rules = {}
                counting_rules["port"] = processPort(row[2])
                counting_rules["ip_address"] = processIPAddress(row[3])
                
                # Appends to the rules which share the same categorical data
                self.rules[key].append(counting_rules)
    
    def __generate_key(self, arr):
        # This method is used more than once and can be easily modified
        # to change the way the key is generated
        s = ','.join(map(str, arr))
        return s

    def accept_packet(self, direction, protocol, port, ip_address):
        
        # Using the categorical attributes of the packet generate key to search with
        filter_key = self.__generate_key([direction, protocol])
        
        if filter_key not in self.rules:
             return False
        
        rules_filtered = self.rules[filter_key]

        packet_properties = {}
        packet_properties["port"] = port
        packet_properties["ip_address"] = processIPAddress(str(ip_address))[0]

        # Made a strong effort to use keys here instead of explicit values
        # like "port" or "ip_address"
        # so that this code could be easily extended if other attributes were added
        # like indentification information

        for rule in rules_filtered:
            
            # This will not change if all checks pass
            state = True

            for key in rule:
                
                # Can very easily compare when it's not a ranged rule
                if len(rule[key]) == 1:
                    if rule[key][0] != packet_properties[key]:
                        state = False
                        # breaks because no need to check for any other keys in this rule
                        # onto the next one
                        break

                elif len(rule[key]) == 2:
                    
                    # For unique cases like ip_address comparison
                    # however this can be improved if we use an interface
                    # and create a comparison function for these elements
                    if key == "ip_address":
                        if not compareIPAddress(rule[key], packet_properties[key]):
                            state = False
                            break
                    else:
                        if rule[key][0] > packet_properties[key] or rule[key][1] < packet_properties[key]:
                            state = False
                            break
           
            if state == True:
                return True
        
        return False


def create_range(range):
    # if the value is not a range then keep it as a single element array
    # made it a single element array instead of single value for consistency
    # also made ranged values a 2 element array
    if "-" in range:
        return range.split('-')
    return [range]

def processPort(port):
    # Cast values as int so easier to compare
    return [int(i) for i in create_range(port)]

def processIPAddress(ip_address):
    # split IP address into their 4 sections and cast each as int
    raw_IP_string = create_range(ip_address)
    for i in range(len(raw_IP_string)):
        raw_IP_string[i] = [int(i) for i in raw_IP_string[i].split(".")]
    return raw_IP_string

def compareIPAddress(ranged, single):
    # Check if within range from left to right for each section of IP address
    for i in range(4):
        if single[i] < ranged[0][i] or single[i] > ranged[1][i]:
            return False
    return True

# Could have imrpoved by making an interface for non-categorical values
# would have comparison functions and contain the processing functions
# for each type
# The above functions could belong to this non-categorical class
# For now they are stand-alone

# class NonCategorical:  
#     def process(range): raise NotImplementedError

# class Port(NonCategorical):
#     def __init__():


if __name__ == "__main__":

    fw = Firewall('fw.csv')
    print("ANS", fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"), True)
    print("ANS", fw.accept_packet("inbound", "udp", 53, "192.168.2.1"), True)
    print("ANS", fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"), True)
    print("ANS", fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"), False)
    print("ANS", fw.accept_packet("inbound", "udp", 24, "52.12.48.92"), False)
