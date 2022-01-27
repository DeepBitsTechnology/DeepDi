FROM ubuntu:20.04

WORKDIR /home
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-pip libboost-python-dev libboost-numpy-dev libcpprest-dev wget
RUN pip3 install numpy pyelftools pefile
RUN wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.10.0/onnxruntime-linux-x64-1.10.0.tgz
RUN tar -zxf onnxruntime-linux-x64-1.10.0.tgz --strip-components=2 -C /usr/local/lib --wildcards "*/lib/lib*"
RUN rm onnxruntime-linux-x64-1.10.0.tgz
COPY ./ .
CMD ["bash"]