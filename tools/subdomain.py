import subprocess
import json

# url = input("URL: ")
def subdomain(domain):
    cmd = f"gobuster dns -d {domain} -w /p1rat3/tools/subdomains-top1million-5000.txt -t 100  > /p1rat3/data/subdomain_takeover/subdomain_tmp.txt"

    print(subprocess.run(cmd, shell=True, capture_output=True)
)
    with open("/p1rat3/data/subdomain_takeover/output_sub_domain","w") as outfile:
        lines = (open("/p1rat3/data/subdomain_takeover/subdomain_tmp.txt","r")).readlines()

        
        for line in lines:
            if "Found" in line:
                try:
                    outfile.write(line.split()[-1])
                    outfile.write("\n")
                except:
                    continue


        # out = {"subdomains" : tags}

        # json_out = json.dumps(out)

        # outfile.write(json_out)


        outfile.close()

