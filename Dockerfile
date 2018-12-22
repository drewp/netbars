FROM bang6:5000/base_x86

WORKDIR /opt

RUN apt-get install -y python-libpcap

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY scripts ./scripts
COPY netbars ./netbars
ENV PYTHONPATH=/opt

EXPOSE 3001

CMD [ "python", "scripts/netbars", "--port", "3001", "--iface", "ens6", "--local", "192.168.1.1"]
