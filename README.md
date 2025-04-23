# Zeek @ HackInSDN

This repo contains information about the integration of Zeek into HackInSDN. Zeek is an Open Source Network Security Monitoring Tool, that analyze network traffic in real-time and generates compact, high-fidelity transaction logs, file content, and fully customizable outputs, providing analysts with actionable data (more information: https://zeek.org/).
HackInSDN is a framework for training and experimenting in computer networks and cyber security utilizing programmable testbed infrastructure (more information: https://hackinsdn.ufba.br/en/).
HackInSDN utilizes Zeek security monitoring capabilities to enrich anomaly detection based on the network.

## Getting Started

You can run Zeek integrated with all other HackInSDN components (e.g, by instantiating it on Mininet-Sec) or running with Docker.

HackInSDN Zeek docker image is based on `zeek/zeek:latest` (https://docs.zeek.org/en/master/install.html), and can be executed with:

```
docker run --pull always -d --name zeek hackinsdn/zeek
```

The Docker execution can be customized / enhanced with a few environment variables:

- `ZEEK_INTERFACE`: interface name where zeek will monitor traffic (defaults to `eth0`)
- `ZEEK_DISABLE_CHECKSUMS`: whether or not to disable checksum checks on Zeek packet capture process
- `ZEEK_SCRIPTS`: user-provided scripts to be executed by zeek
- `ZEEK_ARGS`: user-provided extra arguments to be executed on Zeek startup

## Monitoring network traffic with Zeek

On Zeek you can monitor live traffic or you can process trace files. Using this `hackinsdn/zeek` docker image, we focus on monitoring live network traffic, meaning: `hackinsdn/zeek` has to be placed in such a point where it can see all the traffic going to and coming from the Internet (or any other network of interest). For that purpose you also have two options: 1) running zeek inline; 2) running zeek with a mirrored port. 

Running Zeek inline means that the traffic will be received on a certain interface A and forwarded to interface B, while Zeek will capture traffic passing through those interfaces. It is not the focus of this documentation to provide means to enable such forwarding capability, but you can use something as simple as Linux Bridges:

```
ip link add name br0 type bridge
ip link set dev br0 up
ip link set dev eth0 master br0
ip link set dev eth1 master br0
```

Then you configure Zeek execution so that `ZEEK_INTERFACE=br0`.

Running Zeek with mirroring will depend on you enabling mirroring on your network (notice that some vendors may have different names for this feature: mirror port, span port, copy port, network tap, etc.) and then export the mirrored packets to Zeek, and of course setting the `ZEEK_INTERFACE` to the interface name that will receive such mirrored traffic.

## References

- https://docs.zeek.org/en/master/get-started.html
- https://www.activecountermeasures.com/where-do-i-put-my-zeek-sensor/
