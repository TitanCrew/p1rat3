import json
import subprocess


def check_xss(url):

    command = f"python3 /p1rat3/tools/PwnXSS/pwnxss.py -u {url}"
    initial_output = subprocess.run(command, shell=True, capture_output=True)
    
    with open('/p1rat3/data/xss/xss_data', 'wb') as f:
        f.write(initial_output.stdout)
        f.close()

    command = "grep -i -E 'CRITICAL.*POST' /p1rat3/data/xss/xss_data > /p1rat3/data/xss/post ; grep -i -E 'CRITICAL.*GET' /p1rat3/data/xss/xss_data > /p1rat3/data/xss/get"

    subprocess.run(command, shell=True)

    post_file = open("/p1rat3/data/xss/post","r")
    get_file = open("/p1rat3/data/xss/get", "r")
    out_post_file = open("/p1rat3/data/xss/post.json","w")
    out_get_file = open("/p1rat3/data/xss/get.json", "w")


    line_post = 'q'
    out_post_final = []

    while line_post:
        line_post = post_file.readline()
        if "Detected" in line_post:
            x = line_post.split()
            line_post = post_file.readline()
            y = line_post.split("data: ",1)[1]
            

            out_post ={
                "url" : x[-1],
                "data" : eval(y)
            }

            # tmp = "vul_"+ str(count_post)
            # count_post+=1
            # out_post_final[tmp] = out
            out_post_final.append(out_post)

    temp = []
    for dictionary in out_post_final:
        if dictionary not in temp:
            temp.append(dictionary)

    json_obj = json.dumps(temp,indent=4)
    out_post_file.write(json_obj)
    out_post_file.write("\n")

    line_get = 'q'
    out_get_final = []
    while line_get:
        line_get = get_file.readline()
        if "Detected" in line_get:
            x = line_get.split()
            line_get = get_file.readline()

            out_get_final.append(x[-1])
    json_obj = json.dumps(list(set(out_get_final)),indent=4)
    out_get_file.write(json_obj)
    out_get_file.write("\n")
    print("[+] XSS CHECK SUCCESSFUL")
    return
