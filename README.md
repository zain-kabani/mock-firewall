# mock-firewall

A large focus when tackling this problem was efficency and extendibility.

#### Efficiency

Instead of taking the naive approach of iterating through every rule. I wanted to be able to reduce the search space for rules in a very quick and efficient manner. I did this by identifying the categorical attributes of the rules like direction and protocol, combining the two and using them as a key in map to non-categorical attributes which greatly decreases time complexity. The same cannot be done for the port and IP address values because they can be specified as a range and can take on many values. Instead, the keys mentioned above are mapped to an array of rules. Packet acceptance is done by iterating over this array and evaluating each set of ports and IP addresses.

#### Extendibility 

By using dictionaries everywhere I was able to achevie a design which allowed for other attributes to be added to the rules or even the packets. Tried to avoid explicit use of column names but rather iterated over the keys.

#### Improvements

The design of the non-categorical attribute storage could be improved. Defining a standard and being able to deviate in unique cases in an elegant way can be acheived using interface like pattern and inheritance. Other reasons have been specified in comments of the code.

Another improvment can be made by further optimizing the array of non-categorical values so that overlapping ranges and values are combined. However in the case where many attributes are added this would no be very useful since it's unlikely there would be overlapping of many multiple attributes at the same time.

#### Team Interest
I would be interested in working in the Data or Platform teams.