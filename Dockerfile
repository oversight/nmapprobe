FROM python:3.8
RUN apt-get update && apt-get -y install nmap
ENV OS_CONFIG_FOLDER /data/config/nmapprobe/
ADD . /code
WORKDIR /code
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "nmapprobe.py"]
