FROM --platform=amd64 ubuntu:20.04

COPY ./p1rat3/install-nix.sh .
RUN mkdir /p1rat3
ADD p1rat3 /p1rat3
RUN apt update -y 
RUN apt install python3 -y 
RUN apt install python3-pip -y
RUN pip3 install Flask
RUN apt install nmap -y
RUN apt install gobuster -y 
RUN apt install iputils-ping -y 
RUN apt install curl -y 
RUN apt install wget -y 
RUN apt install whois -y 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install dnsutils -y 
RUN apt install unzip -y 
RUN apt install zip -y 
RUN apt install p7zip -y 
RUN apt install git -y
RUN echo "root:pirates" | chpasswd

RUN chmod +x install-nix.sh
RUN bash install-nix.sh

# Change 
RUN wget https://apt.metasploit.com/pool/main/m/metasploit-framework/metasploit-framework_6.2.35%2B20230106112648~1rapid7-1_amd64.deb
RUN dpkg -i metasploit-framework_6.2.35+20230106112648~1rapid7-1_amd64.deb

# RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install openssh-server -yq
# COPY ./sshd_config /etc/ssh/
# RUN service ssh start
EXPOSE 1-65535

CMD ["python3 /p1rat3/main.py","-D"]