acl_content = []
input = []
result = []
string_acl1 = "access-list"
string_acl2 = "interface"
string_acl3 = "ip"
global permit_deny
permit_deny = []
global protocol
protocol = []
global src_ip
src_ip = []
global dst_ip
dst_ip = []
global inp_src_ip
inp_src_ip = []
global inp_dst_ip
inp_dst_ip = []
global inp_protocol
inp_protocol = []
c_protocols = {'20':'FTP','21':'FTP','22':'SSH','161':'SNMP','80':'HTTP'}
index = 0
global StandardACL
StandardACL = True
global connection
connection = []


#function to check the source subnet
def src_match(i):
    global index
    match = False
    if not StandardACL:
        inp_ip_split = inp_src_ip[i].split(".")
    else:
        inp_ip_split = input[i].split(".")
    for j in range(acl_ip_len):
        if src_ip[j] != "any":
            acl_ip_split = src_ip[j].split(".")
            if acl_ip_split[0] == inp_ip_split[0] or acl_ip_split[0] == '0':
                if acl_ip_split[1] == inp_ip_split[1] or acl_ip_split[1] == '0':
                    if acl_ip_split[2] == inp_ip_split[2] or acl_ip_split[2] == '0':
                        if acl_ip_split[3] == inp_ip_split[3] or acl_ip_split[3] == '0':
                            match = True
                            index = j
                            break
    if match:
        match = False
        return True
    else:
        return False
#function to check the destination subnet
def dst_match(i):
    match = False
    inp_dst_ip_split = inp_dst_ip[i].split(".")
    acl_dst_ip_split = dst_ip[index].split(".")
    if acl_dst_ip_split[0] == inp_dst_ip_split[0] or acl_dst_ip_split[0] == '0':
        if acl_dst_ip_split[1] == inp_dst_ip_split[1] or acl_dst_ip_split[1] == '0':
            if acl_dst_ip_split[2] == inp_dst_ip_split[2] or acl_dst_ip_split[2] == '0':
                if acl_dst_ip_split[3] == inp_dst_ip_split[3] or acl_dst_ip_split[3] == '0':
                    if connection[index] == 'ip' :
                        match = True
                    elif inp_protocol[i] == c_protocols[protocol[index]]:  #cehcks for protocols
                        match = True
    if match:
        match = False
        return True
    else:
        return False
#main function that evaluates the standard ACL statements
def evaluate_ip_stdacl():
    for i in range(inp_data_len):
        if input[i] in src_ip: # if the input ip is directly provided in the ACL
            mtch_indx = src_ip.index(input[i])
            if permit_deny[mtch_indx] == "permit":
                result.append(input[i] + "   permitted")
            else:
                result.append(input[i] + "   denied")
        elif src_match(i): #to chelc the subnets
            if permit_deny[index] == "permit":
                result.append(input[i] + "   permitted")
            else:
                result.append(input[i] + "   denied")
        elif "any" in src_ip: # if any ips that are not specified in the ACL statements
            mtch_indx = src_ip.index("any")
            if permit_deny[mtch_indx] == "permit":
                result.append(input[i] + "   permitted")
            else:
                result.append(input[i] + "   denied")
        else:  # Revisit the logic
            result.append(input[i] + "   denied")

#main function that evaluates the extended ACL statements
def evaluate_ip_extacl():
    for i in range(inp_data_len):
        if inp_src_ip[i] in src_ip:  # if the input ip is directly provided in the ACL
            mtch_indx = src_ip.index(inp_src_ip[i])
            if inp_dst_ip[i] == dst_ip[mtch_indx]:
                if connection[mtch_indx] == 'ip' :
                    if permit_deny[mtch_indx] == "permit":
                        result.append(inp_src_ip[i] + "   permitted")
                    else:
                        result.append(inp_src_ip[i] + "   denied")
                else:
                    if inp_protocol[i] == c_protocols[protocol[mtch_indx]] and permit_deny[mtch_indx] == "permit":
                        result.append(inp_src_ip[i] + "   permitted")
                    else:
                        result.append(inp_src_ip[i] + "   denied")
            else:
                result.append(inp_src_ip[i] + "   denied")

        elif src_match(i):  #to check the subnets
            if dst_match(i):
                result.append(inp_src_ip[i] + "   permitted")
            else:
                result.append(inp_src_ip[i] + "   denied")
        elif "any" in src_ip:  # if any ips that are not specified in the ACL statements
            mtch_indx = src_ip.index("any")
            if permit_deny[mtch_indx] == "permit":
                result.append(inp_src_ip[i] + "   permitted")
            else:
                result.append(inp_src_ip[i] + "   denied")
        else:
            result.append(inp_src_ip[i] + "   denied")



with open("extACL.txt",'r') as f1:
    for line in f1:
        line = line.rstrip('\n')
        tmp_split = line.split(" ")
        if tmp_split[0] != '':
            acl_content.append(tmp_split)
        else:
            tmp_split = ' '.join(tmp_split).split()
            acl_content.append(tmp_split)
f1.close()

data_len = len(acl_content)
if '#extendedACL' in acl_content[0]:
    StandardACL = False

if StandardACL:
    for i in range(1,data_len):
        if acl_content[i][0] == string_acl1:
            permit_deny.append(acl_content[i][2])
            src_ip.append(acl_content[i][3])
else:
    for i in range(1, data_len):
        if acl_content[i][0] == string_acl1:
            permit_deny.append(acl_content[i][2])
            connection.append(acl_content[i][3])
            src_ip.append(acl_content[i][4])
        elif acl_content[i][0] != string_acl1 and acl_content[i][0] != string_acl2 and acl_content[i][0] != string_acl3:
            if len(acl_content[i]) > 2:
                dst_ip.append(acl_content[i][0])
                protocol.append(acl_content[i][3])
            else:
                dst_ip.append(acl_content[i][0])

if StandardACL:
    with open("std_acl_input.txt", 'r') as f2:
        for line in f2:
            line = line.rstrip('\n')
            input.append(line)
    f2.close()
else:
    with open("ext_acl_input.txt", 'r') as f2:
        for line in f2:
            line = line.rstrip('\n')
            input.append(line.split(" "))
    f2.close()
f2.close()



inp_data_len = len(input)
if not StandardACL:
    for i in range(inp_data_len):
        inp_src_ip.append(input[i][0])
        inp_dst_ip.append(input[i][1])
        inp_protocol.append(input[i][2])


acl_ip_len = len(src_ip)
if StandardACL:
    evaluate_ip_stdacl()
else:
    evaluate_ip_extacl()

reslt_len = len(result)
ACLresult = open("output.txt",'w')
for i in range(reslt_len):
    ACLresult.write(result[i] + '\n')


ACLresult.close()
