# Zeek @ HackInSDN

This repo contains information about the integration of Zeek into HackInSDN. Zeek is an Open Source Network Security Monitoring Tool, that analyze network traffic in real-time and generates compact, high-fidelity transaction logs, file content, and fully customizable outputs, providing analysts with actionable data (more information: https://zeek.org/).
HackInSDN is a framework for training and experimenting in computer networks and cyber security utilizing programmable testbed infrastructure (more information: https://hackinsdn.ufba.br/en/).
HackInSDN utilizes Zeek security monitoring capabilities to enrich anomaly detection based on the network.

## Getting Started

You can run Zeek integrated with all other HackInSDN components (e.g, by instantiating it on Mininet-Sec) or running with Docker.

HackInSDN Zeek docker image is based on `zeek/zeek:latest` (https://docs.zeek.org/en/master/install.html), and can be executed with:

```
docker pull hackinsdn/zeek
docker run -d --name zeek hackinsdn/zeek
```
