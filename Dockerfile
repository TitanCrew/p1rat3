FROM --platform=amd64 kalilinux/kali-rolling

RUN apt update -y

RUN apt install python3 -y 
RUN apt install python3-pip -y

RUN apt install git -y
RUN apt install iputils-ping -y
RUN apt install curl -y
RUN apt install wget -y
RUN apt install unzip -y
RUN apt install zip -y
RUN apt install dpkg -y

RUN curl https://sh.rustup.rs --output rust.rs
RUN chmod +x rust.rs
RUN /rust.rs -y
RUN git clone https://github.com/RustScan/RustScan.git
WORKDIR /RustScan
RUN $HOME/.cargo/bin/cargo build --release
RUN mv target/release/rustscan /usr/bin
WORKDIR /

RUN apt install nmap -y
RUN apt install gobuster -y
RUN apt install exploitdb -y

# RUN apt install whois -y
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install dnsutils -y
RUN git clone https://github.com/TitanCrew/p1rat3/
WORKDIR /p1rat3
RUN pip3 install -r requirements.txt
ENV wappalyzer_api=V27thSllZy85ohAn9DYi83xlQjICTGS65f2ZKOhk

EXPOSE 8000

CMD ["python3 main.py","-D"]
