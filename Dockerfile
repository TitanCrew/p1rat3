FROM --platform=amd64 ubuntu:20.04

COPY install-nix.sh .
RUN apt update -y 
RUN apt install python3 -y 
RUN apt install python3-pip -y
RUN pip3 install Flask 
# RUN apt install snapd -y 
# RUN apt install feroxbuster 
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
RUN wget https://apt.metasploit.com/pool/main/m/metasploit-framework/metasploit-framework_6.2.33%2B20221227112617~1rapid7-1_amd64.deb
RUN dpkg -i metasploit-framework_6.2.33%2B20221227112617~1rapid7-1_amd64.deb

RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install openssh-server -yq
COPY ./sshd_config /etc/ssh/
RUN service ssh start
EXPOSE 1-65535

CMD ["/usr/sbin/sshd","-D"]